# =============================================================================
# SEPRJ - LAB-WS01 L2 Hardening
# Script 07 - System Services Desnecessarios
# Controlos CIS:
#   5.23 - Remote Procedure Call (RPC) Locator: Disabled
#   5.30 - SSDP Discovery (SSDPSRV): Disabled
#   5.31 - UPnP Device Host (upnphost): Disabled
#
# O que faz:
#   Desativa tres servicos do Windows sem utilidade numa workstation
#   empresarial em dominio, reduzindo a superficie de ataque:
#
#   RPC Locator (RpcLocator): servico legado de localizacao de servidores
#   RPC, sem funcao em Windows moderno (Vista+).
#
#   SSDP Discovery (SSDPSRV): suporte ao protocolo SSDP/UPnP para
#   descoberta de dispositivos na rede. Vetor de reconhecimento de rede.
#
#   UPnP Device Host (upnphost): permite que o Windows actue como host
#   UPnP. Sem utilizacao em workstation empresarial em dominio.
#
# Mecanismo: GPO -> [Service General Setting] no GptTmpl.inf
#   StartupType: 2=Auto, 3=Manual, 4=Disabled
#
# NOTA: Este script verifica se o GptTmpl.inf ja existe (criado pelo
#   Script 01) e adiciona a seccao de servicos de forma segura,
#   mantendo encoding Unicode consistente em todo o ficheiro.
# =============================================================================

$GPOName = "SEPRJ - LAB-WS01 L2 Hardening"

Write-Host ""
Write-Host "=== Script 07 - System Services Desnecessarios ===" -ForegroundColor Cyan
Write-Host "Controlos CIS: 5.23 (RPC Locator) | 5.30 (SSDP) | 5.31 (UPnP)"
Write-Host "Threat: Network reconnaissance / RPC abuse / UPnP exploitation"
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

$gpoId       = $gpo.Id.ToString().ToUpper()
$domain      = (Get-ADDomain).DNSRoot
$secEditPath = "\\$domain\SYSVOL\$domain\Policies\{$gpoId}\Machine\Microsoft\Windows NT\SecEdit"

if (-not (Test-Path $secEditPath)) {
    try {
        New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
        Write-Host "[OK] Pasta SecEdit criada." -ForegroundColor Green
    } catch {
        Write-Host "[ERRO] Nao foi possivel criar pasta SecEdit: $_" -ForegroundColor Red
        exit 1
    }
}

$gptTmplPath = "$secEditPath\GptTmpl.inf"

# Seccao de servicos a adicionar/garantir
$serviceSection = "[Service General Setting]`r`nRpcLocator,4,`r`nSSDPSRV,4,`r`nupnphost,4,`r`n"

if (Test-Path $gptTmplPath) {
    # Ler ficheiro existente (criado pelo Script 01 em Unicode)
    $existingContent = [System.IO.File]::ReadAllText($gptTmplPath, [System.Text.Encoding]::Unicode)

    if ($existingContent -notmatch "\[Service General Setting\]") {
        # Adicionar seccao ao conteudo existente, mantendo Unicode
        $newContent = $existingContent.TrimEnd() + "`r`n`r`n" + $serviceSection
        try {
            [System.IO.File]::WriteAllText($gptTmplPath, $newContent, [System.Text.Encoding]::Unicode)
            Write-Host "[OK] Seccao [Service General Setting] adicionada ao GptTmpl.inf existente" -ForegroundColor Green
        } catch {
            Write-Host "[ERRO] Falha ao escrever GptTmpl.inf: $_" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "[INFO] Seccao [Service General Setting] ja existe no GptTmpl.inf" -ForegroundColor Yellow
    }
} else {
    # Criar GptTmpl.inf novo com todas as seccoes necessarias
    $infContent = "[Unicode]`r`nUnicode=yes`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n`r`n" + $serviceSection
    try {
        [System.IO.File]::WriteAllText($gptTmplPath, $infContent, [System.Text.Encoding]::Unicode)
        Write-Host "[OK] GptTmpl.inf criado com System Services." -ForegroundColor Green
    } catch {
        Write-Host "[ERRO] Falha ao criar GptTmpl.inf: $_" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "[CIS 5.23] RPC Locator  (RpcLocator) -> Disabled" -ForegroundColor Green
Write-Host "[CIS 5.30] SSDP Discovery (SSDPSRV)  -> Disabled" -ForegroundColor Green
Write-Host "[CIS 5.31] UPnP Device Host (upnphost) -> Disabled" -ForegroundColor Green

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
Write-Host "=== Script 07 concluido com sucesso ===" -ForegroundColor Green
Write-Host "Controlos aplicados:"
Write-Host "  [CIS 5.23] RpcLocator  : Startup = Disabled"
Write-Host "  [CIS 5.30] SSDPSRV     : Startup = Disabled"
Write-Host "  [CIS 5.31] upnphost    : Startup = Disabled"
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "TODOS OS 7 SCRIPTS CONCLUIDOS." -ForegroundColor Cyan
Write-Host "PROXIMO PASSO: Na LAB-WS01, executar:" -ForegroundColor Yellow
Write-Host "  gpupdate /force" -ForegroundColor Yellow
Write-Host "  Restart-Computer -Force" -ForegroundColor Yellow
Write-Host "  gpresult /H C:\Temp\RSoP_pos_L2.html /f" -ForegroundColor Yellow
Write-Host "==================================================" -ForegroundColor Cyan
