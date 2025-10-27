<# 
.SYNOPSIS
  Fichier : AD_Auto.ps1 – Durcissement AD/Windows (GPO + DC configs + détection), FR/EN.

.DESCRIPTION
  - CLIENTS GPO : désactive LLMNR, durcit SMB (signing), désactive SMBv1 (client), réduit WPAD/AutoProxy.
  - DC GPO     : LDAP signing + Channel Binding, SMB signing (serveur), désactive SMBv1 (serveur), journaux LDAP 1644.
  - DETECTION  : active “LDAP Interface Events” (1644) pour repérer collectes LDAP massives (ex: SharpHound).
  - OPTIONS    : blocage FW 5355 (LLMNR), désactivation NetBIOS à grande échelle (WinRM), groupe Protected Users.
  - SAFE       : mode par défaut AuditFirst (compat). Mode Enforce une fois validé.
  
.PARAMETERS
  -Mode AuditFirst|Enforce
  -GpoPrefix
  -ClientOUs
  -BlockLLMNRWithFirewall
  -DisableNetBIOSOnClients
  -NetBIOSTargets
  -ProtectedUsersToAdd
  -Language fr|en

.NOTES
  Exécuter dans une session PowerShell élevée avec RSAT (modules ActiveDirectory, GroupPolicy).
  Exécution prudente (audit d’abord) : .\AD-Defense-Automation.ps1 -Mode AuditFirst
  Ajouter les comptes sensibles au groupe Protected Users : .\AD-Defense-Automation.ps1 -ProtectedUsersToAdd 'admin-secours','svc_sql','svc_backup'
  Bloquer LLMNR direct via firewall + désactiver NetBIOS par remoting:
  .\AD-Defense-Automation.ps1 -BlockLLMNRWithFirewall -PushNetBIOSDisableToClients
  ou ciblé :
  .\AD-Defense-Automation.ps1 -PushNetBIOSDisableToClients -NetBIOSTargets 'PC-001','PC-002'
  Passer en mode appliqué (après tests) : 
  .\AD-Defense-Automation.ps1 -Mode Enforce
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [ValidateSet('AuditFirst','Enforce')]
  [string]$Mode = 'AuditFirst',

  [string]$GpoPrefix = 'AD-Defense',

  [string[]]$ClientOUs,

  [switch]$BlockLLMNRWithFirewall,
  [switch]$DisableNetBIOSOnClients,
  [string[]]$NetBIOSTargets,

  [string[]]$ProtectedUsersToAdd,

  [ValidateSet('fr','en')]
  [string]$Language = 'fr'
)

# -------------------- Localisation --------------------
$L = @{
  fr = @{
    CreatingGpo   = "Création GPO '{0}'..."
    GpoExists     = "GPO '{0}' existe (réutilisation)."
    Linking       = "Lien GPO '{0}' -> {1}"
    AlreadyLinked = "GPO '{0}' déjà lié à {1}."
    PushingFW     = "Poussée des règles pare-feu (LLMNR 5355) sur {0} hôte(s)..."
    DisablingNB   = "Désactivation NetBIOS sur {0} hôte(s)..."
    AddedPU       = "Ajouté au groupe Protected Users : {0}"
    PUGroupMiss   = "Groupe 'Protected Users' introuvable : {0}"
    PW2KHasM      = "Le groupe 'Pre-Windows 2000 Compatible Access' contient des membres : on le vide."
    PW2KEmpty     = "'Pre-Windows 2000 Compatible Access' déjà vide."
    PW2KNotFound  = "Groupe 'Pre-Windows 2000 Compatible Access' non trouvé (ok)."
    BaselineOK    = "[OK] Baseline appliquée. Déployez les GPO (gpupdate /force) et validez avant Enforce."
    MissingModule = "Module requis introuvable / Required module missing: {0}. Installez RSAT puis relancez."
  }
  en = @{
    CreatingGpo   = "Creating GPO '{0}'..."
    GpoExists     = "GPO '{0}' exists (reusing)."
    Linking       = "Linking GPO '{0}' -> {1}"
    AlreadyLinked = "GPO '{0}' already linked to {1}."
    PushingFW     = "Pushing firewall rules (LLMNR 5355) to {0} host(s)..."
    DisablingNB   = "Disabling NetBIOS on {0} host(s)..."
    AddedPU       = "Added to Protected Users group: {0}"
    PUGroupMiss   = "'Protected Users' group not found: {0}"
    PW2KHasM      = "'Pre-Windows 2000 Compatible Access' has members: emptying it."
    PW2KEmpty     = "'Pre-Windows 2000 Compatible Access' already empty."
    PW2KNotFound  = "'Pre-Windows 2000 Compatible Access' group not found (ok)."
    BaselineOK    = "[OK] Baseline applied. Push GPOs (gpupdate /force) and validate before Enforce."
    MissingModule = "Module requis introuvable / Required module missing: {0}. Install RSAT then retry."
  }
}

function Write-Localized {
  param(
    [string]$Key,
    [Alias('Args')][object[]]$FormatArgs
  )
  $msg = $L[$Language][$Key]
  if ($FormatArgs) { $msg = $msg -f $FormatArgs }
  Write-Host $msg
}

# -------------------- Helpers (approved verbs) --------------------
function Import-RequiredModule {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Name)
  if (-not (Get-Module -Name $Name -ListAvailable)) {
    throw ($L[$Language]['MissingModule'] -f $Name)
  }
  Import-Module $Name -ErrorAction Stop | Out-Null
}

function New-Or-GetGpo {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Name)
  $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
  if (-not $gpo) {
    Write-Localized -Key 'CreatingGpo' -Args $Name
    $gpo = New-GPO -Name $Name -ErrorAction Stop
  } else {
    Write-Localized -Key 'GpoExists' -Args $Name
  }
  return $gpo
}

function Add-GpoLink {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][Microsoft.GroupPolicy.GPO]$Gpo,
    [Parameter(Mandatory)][string]$TargetDN
  )
  $links = (Get-GPInheritance -Target $TargetDN).GpoLinks
  if ($links | Where-Object { $_.DisplayName -eq $Gpo.DisplayName }) {
    Write-Localized -Key 'AlreadyLinked' -Args @($Gpo.DisplayName, $TargetDN)
  } else {
    Write-Localized -Key 'Linking' -Args @($Gpo.DisplayName, $TargetDN)
    New-GPLink -Name $Gpo.DisplayName -Target $TargetDN -Enforced:$false | Out-Null
  }
}

function Set-GpoReg {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$GpoName,
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][string]$ValueName,
    [ValidateSet('String','ExpandString','Binary','DWord','MultiString','QWord')]
    [string]$Type,
    [Parameter(Mandatory)]$Value
  )
  Set-GPRegistryValue -Name $GpoName -Key $Key -ValueName $ValueName -Type $Type -Value $Value | Out-Null
}

# -------------------- Contexte AD --------------------
Import-RequiredModule ActiveDirectory
Import-RequiredModule GroupPolicy

$domain   = Get-ADDomain
$DomainDN = $domain.DistinguishedName
$DefaultDCOU = "OU=Domain Controllers,$DomainDN"

# -------------------- GPO Clients --------------------
$gpoClientsName = "$GpoPrefix - Clients"
$gpoClients = New-Or-GetGpo -Name $gpoClientsName

# LLMNR off
Set-GpoReg -GpoName $gpoClientsName `
  -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
  -ValueName 'EnableMulticast' -Type DWord -Value 0

# SMB signing – client
Set-GpoReg -GpoName $gpoClientsName `
  -Key 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
  -ValueName 'EnableSecuritySignature' -Type DWord -Value 1
Set-GpoReg -GpoName $gpoClientsName `
  -Key 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
  -ValueName 'RequireSecuritySignature' -Type DWord -Value 1

# SMBv1 client off
Set-GpoReg -GpoName $gpoClientsName `
  -Key 'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10' `
  -ValueName 'Start' -Type DWord -Value 4

# Réduction WPAD/AutoProxy
Set-GpoReg -GpoName $gpoClientsName `
  -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' `
  -ValueName 'AutoDetect' -Type DWord -Value 0
Set-GpoReg -GpoName $gpoClientsName `
  -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' `
  -ValueName 'EnableAutoProxyResultCache' -Type DWord -Value 0
Set-GpoReg -GpoName $gpoClientsName `
  -Key 'HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc' `
  -ValueName 'Start' -Type DWord -Value 4

# Lier GPO Clients
if ($ClientOUs -and $ClientOUs.Count -gt 0) {
  foreach ($ou in $ClientOUs) { Add-GpoLink -Gpo $gpoClients -TargetDN $ou }
} else {
  Add-GpoLink -Gpo $gpoClients -TargetDN $DomainDN
}

# -------------------- GPO Domain Controllers --------------------
$gpoDcName = "$GpoPrefix - Domain Controllers"
$gpoDc = New-Or-GetGpo -Name $gpoDcName

# LDAP Signing
$ldapIntegrity = if ($Mode -eq 'Enforce') { 2 } else { 1 }  # 2=always, 1=compatible
Set-GpoReg -GpoName $gpoDcName `
  -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
  -ValueName 'LDAPServerIntegrity' -Type DWord -Value $ldapIntegrity

# Channel Binding LDAP
$cbValue = if ($Mode -eq 'Enforce') { 2 } else { 1 }        # 2=Always, 1=Enabled
Set-GpoReg -GpoName $gpoDcName `
  -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
  -ValueName 'LdapEnforceChannelBinding' -Type DWord -Value $cbValue

# SMB signing – serveur
Set-GpoReg -GpoName $gpoDcName `
  -Key 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
  -ValueName 'EnableSecuritySignature' -Type DWord -Value 1
Set-GpoReg -GpoName $gpoDcName `
  -Key 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
  -ValueName 'RequireSecuritySignature' -Type DWord -Value 1

# SMBv1 serveur off
Set-GpoReg -GpoName $gpoDcName `
  -Key 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
  -ValueName 'SMB1' -Type DWord -Value 0

# Logs LDAP 1644
Set-GpoReg -GpoName $gpoDcName `
  -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' `
  -ValueName '16 LDAP Interface Events' -Type DWord -Value 2

# Lier GPO DC
Add-GpoLink -Gpo $gpoDc -TargetDN $DefaultDCOU

# -------------------- Remoting (optionnel) --------------------
function Get-WindowsDomainComputers {
  Get-ADComputer -Filter "OperatingSystem -like '*Windows*' -and Enabled -eq 'true'" -Properties OperatingSystem |
    Select-Object -ExpandProperty Name
}

function Set-LLMNRFirewallBlock {
  [CmdletBinding()]
  param([string[]]$Targets)
  Write-Localized -Key 'PushingFW' -Args $Targets.Count
  $script = {
    $rules = @(
      @{Name='Block LLMNR In UDP 5355'; Dir='in';  Prot='UDP'; Port=5355},
      @{Name='Block LLMNR In TCP 5355'; Dir='in';  Prot='TCP'; Port=5355},
      @{Name='Block LLMNR Out UDP 5355';Dir='out'; Prot='UDP'; Port=5355},
      @{Name='Block LLMNR Out TCP 5355';Dir='out'; Prot='TCP'; Port=5355}
    )
    foreach ($r in $rules) {
      if (-not (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $r.Name -Direction $r.Dir -Action Block -Protocol $r.Prot -LocalPort $r.Port | Out-Null
      }
    }
  }
  Invoke-Command -ComputerName $Targets -ScriptBlock $script -ErrorAction Continue
}

function Disable-NetBIOSOnTargets {
  [CmdletBinding()]
  param([string[]]$Targets)
  Write-Localized -Key 'DisablingNB' -Args $Targets.Count
  $script = {
    $ifaces = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
    foreach ($i in $ifaces) { try { $null = $i.SetTcpipNetbios(2) } catch {} }  # 2 = Disable NetBIOS
  }
  Invoke-Command -ComputerName $Targets -ScriptBlock $script -ErrorAction Continue
}

if ($BlockLLMNRWithFirewall.IsPresent) {
  $targets = Get-WindowsDomainComputers
  Set-LLMNRFirewallBlock -Targets $targets
}

if ($DisableNetBIOSOnClients.IsPresent) {
  $targets = if ($NetBIOSTargets) { $NetBIOSTargets } else { Get-WindowsDomainComputers }
  Disable-NetBIOSOnTargets -Targets $targets
}

# -------------------- Protected Users (optionnel) --------------------
if ($ProtectedUsersToAdd -and $ProtectedUsersToAdd.Count -gt 0) {
  try {
    $grp = Get-ADGroup 'Protected Users' -ErrorAction Stop
    foreach ($u in $ProtectedUsersToAdd) {
      try {
        Add-ADGroupMember -Identity $grp -Members $u -ErrorAction Stop
        Write-Localized -Key 'AddedPU' -Args $u
      } catch {
        Write-Warning $_
      }
    }
  } catch {
    Write-Localized -Key 'PUGroupMiss' -Args $_
  }
}

# -------------------- Nettoyage PW2K compat --------------------
try {
  $pw2k = Get-ADGroup 'Pre-Windows 2000 Compatible Access' -ErrorAction Stop
  $members = Get-ADGroupMember $pw2k -Recursive -ErrorAction SilentlyContinue
  if ($members) {
    Write-Localized -Key 'PW2KHasM'
    foreach ($m in $members) { try { Remove-ADGroupMember -Identity $pw2k -Members $m -Confirm:$false } catch {} }
  } else {
    Write-Localized -Key 'PW2KEmpty'
  }
} catch {
  Write-Localized -Key 'PW2KNotFound'
}

Write-Localized -Key 'BaselineOK'
