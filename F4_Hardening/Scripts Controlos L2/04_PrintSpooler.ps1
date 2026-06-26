# =============================================================================
# SEPRJ - LAB-WS01 L2 Hardening
# Script 04 - Print Spooler (PrintNightmare)
# Controlos CIS:
#   18.7.1  - Allow Print Spooler to accept client connections: Disabled
#   18.7.12 - Point and Print: elevation prompt on new driver install
#   18.7.13 - Point and Print: elevation prompt on driver update
#
# O que faz:
#   - Desativa a capacidade do Print Spooler aceitar ligacoes remotas,
#     eliminando o vetor PrintNightmare (CVE-2021-34527).
#   - Exige elevacao administrativa ao instalar ou actualizar drivers
#     de impressora via Point and Print.
#
# Impacto operacional: Baixo.
#   No laboratorio nao existem impressoras partilhadas - impacto nulo.
# =============================================================================

$GPOName = "SEPRJ - LAB-WS01 L2 Hardening"

Write-Host ""
Write-Host "=== Script 04 - Print Spooler (PrintNightmare) ===" -ForegroundColor Cyan
Write-Host "Controlos CIS: 18.7.1 | 18.7.12 | 18.7.13"
Write-Host "Threat: PrintNightmare (CVE-2021-34527) / Malicious driver install"
Write-Host ""

try {
    $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
    Write-Host "[OK] GPO encontrada: $($gpo.DisplayName)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] GPO nao encontrada: $GPOName" -ForegroundColor Red
    Write-Host "       Detalhe: $_"
    exit 1
}

Write-Host ""

# CIS 18.7.1 - Allow Print Spooler to accept client connections: Disabled
# RegisterSpoolerRemoteRpcEndPoint = 2 (Disabled)
Write-Host "[CIS 18.7.1] Print Spooler: disable client connections..."
try {
    Set-GPRegistryValue `
        -Name $GPOName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
        -ValueName "RegisterSpoolerRemoteRpcEndPoint" `
        -Type DWord `
        -Value 2
    Write-Host "[OK] RegisterSpoolerRemoteRpcEndPoint = 2 (Disabled)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] $_" -ForegroundColor Red; exit 1
}

# CIS 18.7.12 - Point and Print: elevation prompt on new driver install
# NoWarningNoElevationOnInstall = 0 (warning + elevation prompt)
Write-Host "[CIS 18.7.12] Point and Print: elevation prompt on new driver install..."
try {
    Set-GPRegistryValue `
        -Name $GPOName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
        -ValueName "NoWarningNoElevationOnInstall" `
        -Type DWord `
        -Value 0
    Write-Host "[OK] NoWarningNoElevationOnInstall = 0 (warning + elevation prompt)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] $_" -ForegroundColor Red; exit 1
}

# CIS 18.7.13 - Point and Print: elevation prompt on driver update
# UpdatePromptSettings = 0 (warning + elevation prompt)
Write-Host "[CIS 18.7.13] Point and Print: elevation prompt on driver update..."
try {
    Set-GPRegistryValue `
        -Name $GPOName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
        -ValueName "UpdatePromptSettings" `
        -Type DWord `
        -Value 0
    Write-Host "[OK] UpdatePromptSettings = 0 (warning + elevation prompt)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] $_" -ForegroundColor Red; exit 1
}

Write-Host ""
Write-Host "=== Script 04 concluido com sucesso ===" -ForegroundColor Green
Write-Host "Controlos aplicados:"
Write-Host "  [CIS 18.7.1]  Print Spooler remote connections: Disabled"
Write-Host "  [CIS 18.7.12] Point and Print new install: Elevation prompt required"
Write-Host "  [CIS 18.7.13] Point and Print driver update: Elevation prompt required"
Write-Host ""
Write-Host "PROXIMO PASSO: Executar 05_AdvancedAudit.ps1" -ForegroundColor Yellow
