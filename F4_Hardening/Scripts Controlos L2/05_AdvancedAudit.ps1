# =============================================================================
# SEPRJ - LAB-WS01 L2 Hardening
# Script 05 - Advanced Audit Policy
# Controlos CIS:
#   17.2.1   - Audit Application Group Management: Success and Failure
#   17.5.3   - Audit Logoff: Success
#   17.7.3   - Audit Authorization Policy Change: Success
#   18.9.3.1 - Include command line in process creation events: Enabled
#
# O que faz:
#   - Activa registo de eventos de gestao de grupos de aplicacao
#   - Completa o par Logon/Logoff para rastreabilidade de sessoes
#   - Regista alteracoes a politicas de autorizacao (ACLs, permissoes)
#   - Inclui linha de comando completa nos eventos Event ID 4688
#     (essencial para detecao de LOLBins e execucao maliciosa via PS/cmd)
#
# Mecanismo: audit.csv escrito em SYSVOL (UTF-8 sem BOM obrigatorio)
#            + Administrative Template via Set-GPRegistryValue
#
# Pre-requisito: modulo ActiveDirectory (RSAT) disponivel no DC onde
#               este script e executado (LAB-DC01).
# =============================================================================

$GPOName = "SEPRJ - LAB-WS01 L2 Hardening"

Write-Host ""
Write-Host "=== Script 05 - Advanced Audit Policy ===" -ForegroundColor Cyan
Write-Host "Controlos CIS: 17.2.1 | 17.5.3 | 17.7.3 | 18.9.3.1"
Write-Host ""

# Verificar modulo ActiveDirectory
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "[ERRO] Modulo ActiveDirectory nao disponivel." -ForegroundColor Red
    Write-Host "       Execute este script no LAB-DC01 ou instale RSAT."
    exit 1
}

try {
    $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
    Write-Host "[OK] GPO encontrada: $($gpo.DisplayName)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] GPO nao encontrada: $GPOName" -ForegroundColor Red
    Write-Host "       Detalhe: $_"
    exit 1
}

# Construir caminho SYSVOL para as audit policies
$gpoId     = $gpo.Id.ToString().ToUpper()
$domain    = (Get-ADDomain).DNSRoot
$auditPath = "\\$domain\SYSVOL\$domain\Policies\{$gpoId}\Machine\Microsoft\Windows NT\Audit"

if (-not (Test-Path $auditPath)) {
    try {
        New-Item -Path $auditPath -ItemType Directory -Force | Out-Null
        Write-Host "[OK] Pasta Audit criada: $auditPath" -ForegroundColor Green
    } catch {
        Write-Host "[ERRO] Nao foi possivel criar pasta Audit: $_" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""

# CIS 17.2.1, 17.5.3, 17.7.3 - Advanced Audit Policies via audit.csv
# CRITICO: UTF-8 sem BOM - usar WriteAllText em vez de Out-File
# Setting Value: 0=No Auditing, 1=Success, 2=Failure, 3=Success and Failure
Write-Host "[CIS 17.2.1] Audit Application Group Management: Success and Failure..."
Write-Host "[CIS 17.5.3] Audit Logoff: Success..."
Write-Host "[CIS 17.7.3] Audit Authorization Policy Change: Success..."

$auditCsvContent = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value`r`n" +
                   ",System,Application Group Management,{0CCE9236-69AE-11D9-BED3-505054503030},Success and Failure,,3`r`n" +
                   ",System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,,1`r`n" +
                   ",System,Authorization Policy Change,{0CCE9230-69AE-11D9-BED3-505054503030},Success,,1`r`n"

$csvPath = "$auditPath\audit.csv"
try {
    # UTF-8 sem BOM - obrigatorio para o auditpol processar correctamente
    [System.IO.File]::WriteAllText($csvPath, $auditCsvContent, [System.Text.UTF8Encoding]::new($false))
    Write-Host "[OK] audit.csv escrito (UTF-8 sem BOM) em: $csvPath" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao escrever audit.csv: $_" -ForegroundColor Red
    exit 1
}

# CIS 18.9.3.1 - Include command line in process creation events
# Activa a inclusao da linha de comando completa no Event ID 4688.
Write-Host ""
Write-Host "[CIS 18.9.3.1] Include command line in process creation events..."
try {
    Set-GPRegistryValue `
        -Name $GPOName `
        -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -ValueName "ProcessCreationIncludeCmdLine_Enabled" `
        -Type DWord `
        -Value 1
    Write-Host "[OK] ProcessCreationIncludeCmdLine_Enabled = 1 (Enabled)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] $_" -ForegroundColor Red; exit 1
}

# Incrementar versao GPT.INI para forcar re-aplicacao da GPO
$gptIniPath = "\\$domain\SYSVOL\$domain\Policies\{$gpoId}\GPT.INI"
if (Test-Path $gptIniPath) {
    try {
        $ini = Get-Content $gptIniPath
        $versionLine = $ini | Where-Object { $_ -match "^Version=" }
        if ($versionLine) {
            $currentVersion = [int]($versionLine -replace "Version=","")
            $newVersion     = $currentVersion + 1
            $ini = $ini -replace "^Version=.*", "Version=$newVersion"
            $ini | Set-Content $gptIniPath -Encoding ASCII
            Write-Host "[OK] GPT.INI versao actualizada: $currentVersion -> $newVersion" -ForegroundColor Green
        }
    } catch {
        Write-Host "[AVISO] Nao foi possivel actualizar GPT.INI: $_" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== Script 05 concluido com sucesso ===" -ForegroundColor Green
Write-Host "Controlos aplicados:"
Write-Host "  [CIS 17.2.1]   Application Group Management: Success and Failure"
Write-Host "  [CIS 17.5.3]   Logoff: Success"
Write-Host "  [CIS 17.7.3]   Authorization Policy Change: Success"
Write-Host "  [CIS 18.9.3.1] Command line in process creation: Enabled"
Write-Host ""
Write-Host "PROXIMO PASSO: Executar 06_FirewallLogging.ps1" -ForegroundColor Yellow
