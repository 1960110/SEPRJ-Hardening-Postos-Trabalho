Pós-Graduação em Segurança da Informação, Cibersegurança e Privacidade de Dados — ISEP 2025/2026  
Projeto Final da disciplina de SEPRJ
Tema: Hardening de Postos de Trabalho Windows 11 Enterprise
Autor: Carlos Miguel Dinis da Silva (n.º 1960110)
---

Conteúdo do Repositório
F3_Baseline/
Evidências da fase de Medição (estado inicial, pré-hardening).  
Inclui relatórios CIS-CAT Lite, output Nmap e relatório OpenVAS da LAB-WS01 no estado original.
F4_Hardening/
Evidências da fase de Endurecimento.  
Inclui o relatório RSoP após aplicação do baseline Microsoft SCT L1 via GPO, o relatório CIS-CAT pós-L1, a matriz de decisão dos controlos L2 (análise de risco NIST SP 800-30 / CSET) e os relatórios exportados do CSET.
F5_Validacao/
Evidências da fase de Validação (estado final, pós-aplicação de todos os controlos).  
Inclui relatório CIS-CAT pós-L2, output Nmap final e relatório OpenVAS de validação.
Scripts_L2/
Scripts PowerShell utilizados para configurar os controlos CIS L2 selecionados por análise de risco.  
Cada script corresponde a um grupo de controlos e foi executado na LAB-DC01, configurando a GPO `SEPRJ - LAB-WS01 L2 Hardening` no Active Directory.
Script	Controlos CIS	O que configura
`01_AccountLockout.ps1`	1.2.1, 1.2.4	Lockout duration e observation window → 15 min
`02_LSASS.ps1`	18.9.27.2	LSASS Protected Process Light com UEFI Lock
`03_SMB_Network.ps1`	18.6.7.4/6/7, 18.6.8.6, 18.6.14.1, 18.6.4.1	SMB 3.1.1 mínimo, rate limiter, Hardened UNC Paths, desativação mDNS
`04_PrintSpooler.ps1`	18.7.1, 18.7.12, 18.7.13	Desativação de ligações remotas ao Print Spooler (PrintNightmare)
`05_AdvancedAudit.ps1`	17.2.1, 17.5.3, 17.7.3, 18.9.3.1	Auditoria avançada + linha de comando no Event ID 4688
`06_FirewallLogging.ps1`	9.1.4, 9.2.4, 9.3.6	Logging de firewall nos perfis Domain, Private e Public
`07_SystemServices.ps1`	5.23, 5.30, 5.31	Desativação de RPC Locator, SSDP Discovery e UPnP Device Host


