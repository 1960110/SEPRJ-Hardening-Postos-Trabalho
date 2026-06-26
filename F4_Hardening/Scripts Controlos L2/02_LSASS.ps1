# =============================================================================
# SEPRJ - LAB-WS01 L2 Hardening
# Script 02 - LSASS Protected Process
# Controlo CIS: 18.9.27.2
#
# O que faz: Configura o processo LSASS para correr como Protected Process
# Light (PPL). Impede ferramentas como Mimikatz de fazer dump de credenciais
# em memoria (Pass-the-Hash, Pass-the-Ticket).
#
# Mecanismo: Chave de registo via Set-GPRegistryValue
# HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> RunAsPPL = 2
# Valor 2 = Enabled with UEFI Lock (mais seguro que valor 1)
#
# Pre-requisito verificado: Confirm-SecureBootUEFI = True (LAB-WS01)
# Sem conflito com AV: apenas Windows Defender instalado na LAB-WS01
# =============================================================================

$GPOName = "SEPRJ - LAB-WS01 L2 Hardening"

Write-Host ""
Write-Host "=== Script 02 - LSASS Protected Process ===" -ForegroundColor Cyan
Write-Host "Controlo CIS: 18.9.27.2 | Threat: Credential dumping (Mimikatz)"
Write-Host ""

try {
    $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
    Write-Host "[OK] GPO encontrada: $($gpo.DisplayName)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] GPO nao encontrada: $GPOName" -ForegroundColor Red
    Write-Host "       Detalhe: $_"
    exit 1
}

# CIS 18.9.27.2 - LSASS como Protected Process Light com UEFI Lock
# RunAsPPL = 2 significa "Enabled with UEFI Lock"
# (valor 1 seria "Enabled" sem UEFI Lock - menos seguro)
try {
    Set-GPRegistryValue `
        -Name $GPOName `
        -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
        -ValueName "RunAsPPL" `
        -Type DWord `
        -Value 2
    Write-Host "[OK] RunAsPPL = 2 (Enabled with UEFI Lock) configurado" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao configurar RunAsPPL: $_" -ForegroundColor Red
    exit 1
}

# Nota: RunAsPPLBoot removido - nao faz parte do CIS 18.9.27.2 e pode
# ter comportamento indefinido em ambiente de virtualizacao aninhada.

Write-Host ""
Write-Host "=== Script 02 concluido com sucesso ===" -ForegroundColor Green
Write-Host "Controlos aplicados:"
Write-Host "  [CIS 18.9.27.2] LSASS RunAsPPL = 2 (Enabled with UEFI Lock)"
Write-Host "  Nota: Este controlo so e efectivo apos reinicio da LAB-WS01."
Write-Host ""
Write-Host "PROXIMO PASSO: Executar 03_SMB_Network.ps1" -ForegroundColor Yellow
