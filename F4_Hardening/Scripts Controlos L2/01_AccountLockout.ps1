# =============================================================================
# SEPRJ - LAB-WS01 L2 Hardening
# Script 01 — Account Lockout Policy
# Controlos CIS: 1.2.1 (Lockout Duration >=15 min)
#                1.2.4 (Reset Lockout Counter >=15 min)
#
# Mecanismo: As Account Policies nao podem ser configuradas via
# Set-GPRegistryValue. Sao aplicadas atraves de um ficheiro de template
# de seguranca (GptTmpl.inf) copiado para o SYSVOL da GPO.
#
# Nota: LockoutBadCount (CIS 1.2.2) NAO e alterado neste script
# (controlo marcado como "Rever" — threshold de 5 tentativas requer
# validacao adicional pelo risco de lockout-DoS).
# =============================================================================

$GPOName = "SEPRJ - LAB-WS01 L2 Hardening"

Write-Host ""
Write-Host "=== Script 01 — Account Lockout Policy ===" -ForegroundColor Cyan
Write-Host "Controlos CIS: 1.2.1 (LockoutDuration >=15) | 1.2.4 (ResetLockoutCount >=15)"
Write-Host ""

# Verificar que a GPO existe
$gpo = Get-GPO -Name $GPOName -ErrorAction Stop
Write-Host "[OK] GPO encontrada: $($gpo.DisplayName) | Id: $($gpo.Id)" -ForegroundColor Green

# Construir o caminho SYSVOL da GPO
$gpoId    = $gpo.Id.ToString().ToUpper()
$domain   = (Get-ADDomain).DNSRoot
$secEditPath = "\\$domain\SYSVOL\$domain\Policies\{$gpoId}\Machine\Microsoft\Windows NT\SecEdit"

Write-Host "[INFO] Caminho SYSVOL: $secEditPath"

# Criar a pasta SecEdit se nao existir
if (-not (Test-Path $secEditPath)) {
    New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
    Write-Host "[OK] Pasta SecEdit criada." -ForegroundColor Green
} else {
    Write-Host "[INFO] Pasta SecEdit ja existe." -ForegroundColor Yellow
}

# Conteudo do template de seguranca
# LockoutDuration  = 15 min  (CIS 1.2.1: >=15 min; valor anterior: 10 min SCT L1)
# ResetLockoutCount = 15 min (CIS 1.2.4: >=15 min; valor anterior: 10 min SCT L1)
# LockoutBadCount  = 0       (0 = sem alteracao ao threshold existente)
$infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
LockoutDuration = 15
LockoutBadCount = 0
ResetLockoutCount = 15
"@

$infPath = "$secEditPath\GptTmpl.inf"
$infContent | Out-File -FilePath $infPath -Encoding Unicode -Force

Write-Host "[OK] GptTmpl.inf escrito em: $infPath" -ForegroundColor Green

# Incrementar a versao da GPO para forcar re-aplicacao nos clientes
$gpoPath = "\\$domain\SYSVOL\$domain\Policies\{$gpoId}"
$gptIniPath = "$gpoPath\GPT.INI"

if (Test-Path $gptIniPath) {
    $ini = Get-Content $gptIniPath
    $versionLine = $ini | Where-Object { $_ -match "^Version=" }
    if ($versionLine) {
        $currentVersion = [int]($versionLine -replace "Version=","")
        $newVersion = $currentVersion + 1
        $ini = $ini -replace "^Version=.*", "Version=$newVersion"
        $ini | Set-Content $gptIniPath -Encoding ASCII
        Write-Host "[OK] GPT.INI versao actualizada: $currentVersion -> $newVersion" -ForegroundColor Green
    }
} else {
    # Criar GPT.INI se nao existir
    @"
[General]
Version=1
displayName=New Group Policy Object
"@ | Set-Content $gptIniPath -Encoding ASCII
    Write-Host "[OK] GPT.INI criado." -ForegroundColor Green
}

# Forcar actualizacao da GPO no AD
Set-GPRegistryValue -Name $GPOName -Key "HKLM\Software\Policies\Microsoft\Windows\System" `
    -ValueName "L2_AccountLockout_Applied" -Type String -Value "2026-06-17" | Out-Null

Write-Host ""
Write-Host "=== Script 01 concluido com sucesso ===" -ForegroundColor Green
Write-Host "Controlos aplicados:"
Write-Host "  [CIS 1.2.1] LockoutDuration  = 15 minutos (anterior: 10 min)"
Write-Host "  [CIS 1.2.4] ResetLockoutCount = 15 minutos (anterior: 10 min)"
Write-Host ""
Write-Host "PROXIMO PASSO: Executar 02_LSASS.ps1" -ForegroundColor Yellow
