# =============================================================================
# SEPRJ - LAB-WS01 L2 Hardening
# Script 03 - SMB / Network Security
# Controlos CIS:
#   18.6.7.4  - SMB Client: Enable authentication rate limiter
#   18.6.7.6  - SMB Client: Mandate minimum version SMB 3.1.1
#   18.6.7.7  - SMB Client: Authentication rate limiter delay >= 2000ms
#   18.6.8.6  - SMB Server: Mandate minimum version SMB 3.1.1
#   18.6.14.1 - Hardened UNC Paths (NETLOGON + SYSVOL)
#   18.6.4.1  - Disable multicast DNS (mDNS)
#
# O que faz:
#   - Impede downgrade de SMB para versoes < 3.1.1 (mitiga SMB relay/MitM)
#   - Limita tentativas de autenticacao SMB (mitiga brute-force SMB)
#   - Protege UNC paths criticos do AD contra intercepcao MitM
#   - Desativa mDNS para eliminar vetor de mDNS/LLMNR poisoning
#
# Pre-requisito: SMBv1 ja desativado (confirmado F3). Windows 11 e
# Windows Server 2022 suportam SMB 3.1.1 nativamente.
# MinSMB2Dialect = 0x0311 = 785 decimal (SMB 3.1.1)
# =============================================================================

$GPOName = "SEPRJ - LAB-WS01 L2 Hardening"

Write-Host ""
Write-Host "=== Script 03 - SMB / Network Security ===" -ForegroundColor Cyan
Write-Host "Controlos CIS: 18.6.7.4 | 18.6.7.6 | 18.6.7.7 | 18.6.8.6 | 18.6.14.1 | 18.6.4.1"
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

# CIS 18.6.7.4 - SMB Client: Enable authentication rate limiter
Write-Host "[CIS 18.6.7.4] SMB Client: Enable authentication rate limiter..."
try {
    Set-GPRegistryValue `
        -Name $GPOName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
        -ValueName "EnableAuthRateLimiter" `
        -Type DWord `
        -Value 1
    Write-Host "[OK] EnableAuthRateLimiter = 1 (Enabled)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] $_" -ForegroundColor Red; exit 1
}

# CIS 18.6.7.6 - SMB Client: Mandate minimum SMB version 3.1.1
# 0x0311 = 785 decimal
Write-Host "[CIS 18.6.7.6] SMB Client: Mandate minimum version 3.1.1..."
try {
    Set-GPRegistryValue `
        -Name $GPOName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
        -ValueName "MinSMB2Dialect" `
        -Type DWord `
        -Value 785
    Write-Host "[OK] MinSMB2Dialect = 785 (0x0311 = SMB 3.1.1)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] $_" -ForegroundColor Red; exit 1
}

# CIS 18.6.7.7 - SMB Client: Authentication rate limiter delay >= 2000ms
Write-Host "[CIS 18.6.7.7] SMB Client: Authentication rate limiter delay = 2000ms..."
try {
    Set-GPRegistryValue `
        -Name $GPOName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
        -ValueName "AuthRateLimiterDelay" `
        -Type DWord `
        -Value 2000
    Write-Host "[OK] AuthRateLimiterDelay = 2000 ms" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] $_" -ForegroundColor Red; exit 1
}

# CIS 18.6.8.6 - SMB Server: Mandate minimum SMB version 3.1.1
Write-Host "[CIS 18.6.8.6] SMB Server: Mandate minimum version 3.1.1..."
try {
    Set-GPRegistryValue `
        -Name $GPOName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" `
        -ValueName "MinSMB2Dialect" `
        -Type DWord `
        -Value 785
    Write-Host "[OK] LanmanServer MinSMB2Dialect = 785 (0x0311 = SMB 3.1.1)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] $_" -ForegroundColor Red; exit 1
}

# CIS 18.6.14.1 - Hardened UNC Paths (NETLOGON + SYSVOL)
Write-Host "[CIS 18.6.14.1] Hardened UNC Paths (NETLOGON + SYSVOL)..."
$uncKey   = "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
$uncValue = "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1"

try {
    Set-GPRegistryValue `
        -Name $GPOName `
        -Key $uncKey `
        -ValueName "\\*\NETLOGON" `
        -Type String `
        -Value $uncValue
    Write-Host "[OK] NETLOGON: $uncValue" -ForegroundColor Green

    Set-GPRegistryValue `
        -Name $GPOName `
        -Key $uncKey `
        -ValueName "\\*\SYSVOL" `
        -Type String `
        -Value $uncValue
    Write-Host "[OK] SYSVOL: $uncValue" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] $_" -ForegroundColor Red; exit 1
}

# CIS 18.6.4.1 - Disable multicast DNS (mDNS)
# O laboratorio tem DNS autoritativo (LAB-DC01) - sem impacto na resolucao de nomes.
Write-Host "[CIS 18.6.4.1] Disable multicast DNS (mDNS)..."
try {
    Set-GPRegistryValue `
        -Name $GPOName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -ValueName "EnableMulticast" `
        -Type DWord `
        -Value 0
    Write-Host "[OK] EnableMulticast = 0 (mDNS Disabled)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] $_" -ForegroundColor Red; exit 1
}

Write-Host ""
Write-Host "=== Script 03 concluido com sucesso ===" -ForegroundColor Green
Write-Host "Controlos aplicados:"
Write-Host "  [CIS 18.6.7.4]  SMB Client auth rate limiter: Enabled"
Write-Host "  [CIS 18.6.7.6]  SMB Client min version: 3.1.1 (0x0311)"
Write-Host "  [CIS 18.6.7.7]  SMB Client rate limiter delay: 2000ms"
Write-Host "  [CIS 18.6.8.6]  SMB Server min version: 3.1.1 (0x0311)"
Write-Host "  [CIS 18.6.14.1] Hardened UNC Paths: NETLOGON + SYSVOL"
Write-Host "  [CIS 18.6.4.1]  mDNS: Disabled"
Write-Host ""
Write-Host "PROXIMO PASSO: Executar 04_PrintSpooler.ps1" -ForegroundColor Yellow
