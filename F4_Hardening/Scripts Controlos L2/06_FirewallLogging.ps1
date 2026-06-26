# =============================================================================
# SEPRJ - LAB-WS01 L2 Hardening
# Script 06 - Windows Firewall Logging
# Controlos CIS:
#   9.1.4 - Windows Firewall Domain Profile: Logging Name configured
#   9.2.4 - Windows Firewall Private Profile: Logging Name configured
#   9.3.6 - Windows Firewall Public Profile: Logging Name configured
#
# O que faz:
#   Activa o registo de firewall para os tres perfis (Domain, Private, Public).
#   Sem este controlo o Windows Firewall nao grava tentativas de ligacao
#   bloqueadas, impossibilitando analise forense e detecao de port scanning
#   e lateral movement.
#
# Mecanismo: Set-GPRegistryValue para LogFilePath e LogFileSize (CIS-mandated).
#   LogDroppedPackets e LogSuccessfulConnections sao configurados via
#   registo de politica de firewall - confirmar efeito com gpresult apos
#   gpupdate /force.
#
# Tamanho maximo: 16384 KB (16 MB) por perfil.
# =============================================================================

$GPOName = "SEPRJ - LAB-WS01 L2 Hardening"

Write-Host ""
Write-Host "=== Script 06 - Windows Firewall Logging ===" -ForegroundColor Cyan
Write-Host "Controlos CIS: 9.1.4 (Domain) | 9.2.4 (Private) | 9.3.6 (Public)"
Write-Host "Threat: Undetected network intrusion / Port scanning / Lateral movement"
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

# Caminhos de log para cada perfil (variaveis de ambiente - nao expandir aqui)
$logDomain  = "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
$logPrivate = "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
$logPublic  = "%SystemRoot%\System32\logfiles\firewall\publicfw.log"

# Funcao auxiliar para configurar logging de um perfil
function Set-FirewallProfileLogging {
    param(
        [string]$ProfileLabel,
        [string]$RegistryKey,
        [string]$LogPath
    )
    Write-Host "Firewall $ProfileLabel Profile Logging..."
    try {
        Set-GPRegistryValue -Name $GPOName -Key $RegistryKey `
            -ValueName "LogFilePath" -Type String -Value $LogPath
        Write-Host "  [OK] LogFilePath = $LogPath" -ForegroundColor Green

        Set-GPRegistryValue -Name $GPOName -Key $RegistryKey `
            -ValueName "LogFileSize" -Type DWord -Value 16384
        Write-Host "  [OK] LogFileSize = 16384 KB" -ForegroundColor Green

        Set-GPRegistryValue -Name $GPOName -Key $RegistryKey `
            -ValueName "LogDroppedPackets" -Type DWord -Value 1
        Write-Host "  [OK] LogDroppedPackets = 1 (Enabled)" -ForegroundColor Green

        Set-GPRegistryValue -Name $GPOName -Key $RegistryKey `
            -ValueName "LogSuccessfulConnections" -Type DWord -Value 1
        Write-Host "  [OK] LogSuccessfulConnections = 1 (Enabled)" -ForegroundColor Green
    } catch {
        Write-Host "  [ERRO] Falha no perfil ${ProfileLabel}: $_" -ForegroundColor Red
        exit 1
    }
}

# CIS 9.1.4 - Domain Profile
Write-Host "[CIS 9.1.4] " -NoNewline
Set-FirewallProfileLogging `
    -ProfileLabel "Domain" `
    -RegistryKey  "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
    -LogPath      $logDomain

Write-Host ""

# CIS 9.2.4 - Private Profile
Write-Host "[CIS 9.2.4] " -NoNewline
Set-FirewallProfileLogging `
    -ProfileLabel "Private" `
    -RegistryKey  "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" `
    -LogPath      $logPrivate

Write-Host ""

# CIS 9.3.6 - Public Profile
Write-Host "[CIS 9.3.6] " -NoNewline
Set-FirewallProfileLogging `
    -ProfileLabel "Public" `
    -RegistryKey  "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" `
    -LogPath      $logPublic

Write-Host ""
Write-Host "=== Script 06 concluido com sucesso ===" -ForegroundColor Green
Write-Host "Controlos aplicados:"
Write-Host "  [CIS 9.1.4] Domain  log: $logDomain"
Write-Host "  [CIS 9.2.4] Private log: $logPrivate"
Write-Host "  [CIS 9.3.6] Public  log: $logPublic"
Write-Host "  Dropped packets e successful connections: registados nos 3 perfis"
Write-Host ""
Write-Host "AVISO: Confirmar efeito com gpresult /H apos gpupdate /force" -ForegroundColor Yellow
Write-Host "PROXIMO PASSO: Executar 07_SystemServices.ps1" -ForegroundColor Yellow
