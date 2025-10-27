## Repo snapshot

- Single-primary script: `AD_Auto.ps1` (PowerShell). This repository contains a defensive Active Directory hardening script and a minimal `README.md`.

## High-level architecture / intent

- Purpose: safe, idempotent baseline hardening for AD environments (creates/updates GPOs, sets DC and client registry policies, optional remote client changes).
- Major components (all in `AD_Auto.ps1`):
  - GPO creation/lookup helpers: `New-Or-GetGpo`, `Link-Gpo`.
  - Registry GPO writer: `Set-GpoReg` (wraps `Set-GPRegistryValue`).
  - AD context and discovery: `Get-ADDomain`, `Get-ADComputer`, `Get-ADGroup` usage.
  - Optional remoting actions: `Push-LLMNR-Firewall`, `Push-Disable-NetBIOS` (use `Invoke-Command`).

## Key developer workflows (how to run / validate)

- Preconditions: run in an elevated PowerShell session on a management workstation or DC with RSAT installed (ActiveDirectory and GroupPolicy modules available).
- Basic dry run / normal run example:

  - Launch elevated PowerShell, then:

    .\AD_Auto.ps1 -Mode AuditFirst -GpoPrefix 'AD-Defense'

  - To apply optional remote actions (requires WinRM/PSRemoting and domain admin rights):

    .\AD_Auto.ps1 -BlockLLMNRWithFirewall -PushNetBIOSDisableToClients

- Quick verification commands (examples used by the script):

  - Check domain and DC OU: `Get-ADDomain` (script stores DistinguishedName in `$DomainDN`, DC OU in `$DefaultDCOU`).
  - Confirm GPO created: `Get-GPO -Name 'AD-Defense - Clients'` (or `$GpoPrefix - Clients`).
  - Inspect a registry GPO value: `Get-GPRegistryValue -Name 'AD-Defense - Domain Controllers' -Key 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -ValueName 'LDAPServerIntegrity'`.
  - After changes, run `gpupdate /force` on targets and validate event IDs (e.g., LDAP logging Event 1644 enabled on DCs).

## Project-specific conventions & patterns for AI edits

- Language / style: script is idiomatic PowerShell with French comments and messages. Preserve existing French wording unless user asks for translation.
- Safety-first default: script defaults to `-Mode AuditFirst`. When changing defaults, respect the two-mode pattern (`AuditFirst` vs `Enforce`) and adjust both registry values and the `$ldapIntegrity`/`$cbValue` computation.
- Reuse helpers: prefer adding or updating small helper functions (`Ensure-Module`, `Set-GpoReg`, `Link-Gpo`) rather than duplicating logic. New helpers should follow the same error-handling style (throw on missing modules, Write-Host/Write-Warning for runtime notes).
- Idempotency: operations intentionally check existence (Get-GPO, Get-NetFirewallRule, group membership). Any change should keep that pattern—avoid unconditional creation or removal.

## Integration points & external dependencies

- Requires RSAT (PowerShell modules: `ActiveDirectory`, `GroupPolicy`). The script calls `Ensure-Module` and will throw if a module is missing.
- Uses Group Policy cmdlets: `Get-GPO`, `New-GPO`, `Set-GPRegistryValue`, `New-GPLink`, `Get-GPInheritance`.
- Remote actions use `Invoke-Command` (WinRM/PSRemoting must be configured and reachable).

## Examples of patterns to follow (copyable snippets from repo)

- Create-or-get a GPO and link it:

  $gpo = New-Or-GetGpo -Name "$GpoPrefix - Clients"
  Link-Gpo -Gpo $gpo -TargetDN $DomainDN

- Set a registry value in a GPO (SMB signing on clients):

  Set-GpoReg -GpoName "$GpoPrefix - Clients" -Key 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -ValueName 'RequireSecuritySignature' -Type DWord -Value 1

## Inputs / outputs contract (short)

- Inputs: script parameters (`-Mode`, `-GpoPrefix`, `-ClientOUs`, `-BlockLLMNRWithFirewall`, `-PushNetBIOSDisableToClients`, `-NetBIOSTargets`, `-ProtectedUsersToAdd`).
- Outputs/effects: GPOs created/updated (`$GpoPrefix - Clients`, `$GpoPrefix - Domain Controllers`), GPO links, registry keys written to those GPOs, optional firewall and NetBIOS changes applied via remoting, Protected Users group membership updated.
- Error modes: missing RSAT modules, insufficient privileges (need domain admin / delegated rights for some ops), WinRM unreachable for remoting, non-existent target OUs/groups.

## Edge cases & checks for an AI agent

- When proposing changes that tighten defaults, ensure a path to keep `AuditFirst` available for testing.
- Any edit touching LDAP/SMB/NetBIOS behavior must mention the verification steps (gpupdate, event logs, connectivity impact).
- Remote operations assume `Invoke-Command` success; detect and handle unreachable hosts.

## What *not* to change without human review

- Do not change the default `-Mode` from `AuditFirst` to `Enforce` silently.
- Avoid mass remote changes without adding clear opt-in flags and dry-run behavior.

---

If you'd like, I can:
- open a PR with this file added, or
- expand the file with template unit-test suggestions or a short CONTRIBUTING.md for runbooks.

Please tell me if any sections are unclear or if you want more examples (for instance, exact verification commands for Event Viewer, or a small test harness to validate GPO registry writes).
