# Security & Data Handling

This document describes the security posture of the Aperture Data Collector for review by information security, compliance, and risk teams. It is written to be verifiable — every claim below can be checked against the source code in this repository.

> **Quick summary:** Read-only script. No telemetry. No secrets collected. All output stays on your machine until you choose to share it. Optional PII anonymization. Every line is open source.

---

## 1. Read-Only Guarantee

The collector **never creates, modifies, or deletes any Azure resource.**

- All Azure access uses read-only cmdlets (`Get-AzVM`, `Get-AzWvdHostPool`, `Get-AzMetric`, etc.) or `Invoke-AzRestMethod` with `-Method GET`.
- The only POST requests are to two Azure **query** APIs that require POST by design:
  - Cost Management query (`Microsoft.CostManagement/query`) — read-only cost reporting DSL
  - Log Analytics query (`Invoke-AzOperationalInsightsQuery`) — read-only KQL execution
- The only `Set-*` cmdlet used is `Set-AzContext` (switches the active subscription in your local session — no resource impact).

You can verify this yourself:

```powershell
# Should return ONLY Set-AzContext (subscription switching):
Select-String -Path .\Collect-ApertureData.ps1 -Pattern 'New-Az|Remove-Az|Set-Az|Update-Az' |
    Where-Object Line -notmatch 'Set-AzContext'
```

## 2. No Telemetry / No Phone-Home

The script contacts **only Microsoft-owned Azure endpoints**:

| Endpoint | Purpose |
|----------|---------|
| `management.azure.com` | ARM resource inventory |
| `api.loganalytics.io` / Log Analytics | KQL query execution |
| `graph.microsoft.com` | Intune device data (only with `-IncludeIntune`) |

There are no calls to third-party services, no usage analytics, no update checks, and no external downloads at runtime. All collected data is written to the **local file system only** — nothing leaves your machine unless you send the ZIP.

## 3. What Is Never Collected

The script does not access or collect:

- **Host pool registration tokens** — never requested from the ARM API
- Passwords, secrets, certificates, or Key Vault contents
- Storage account keys, SAS tokens, or connection strings
- Log Analytics workspace keys
- File share contents, user files, or profile data
- Application or database contents
- Entra ID user attributes beyond UPN (used for session correlation only)
- Network traffic or packet captures
- OS-level configuration (registry, local policies, Group Policy)

## 4. Credential & Token Handling

- Authentication uses standard module-managed sessions (`Connect-AzAccount` via `Az.Accounts`; `Connect-MgGraph` only with `-IncludeIntune`).
- Access tokens are **never written to disk, the console, or the output ZIP**.
- The Graph token handoff for `-IncludeIntune` uses `Get-AzAccessToken -AsSecureString` — the token stays SecureString-wrapped and is passed directly to `Connect-MgGraph`, avoiding a second sign-in prompt.
- No credentials are cached by the script itself; session lifetime is controlled by the Az / Graph modules.

## 5. Least-Privilege Permissions

Core collection requires only:

| Role | Scope |
|------|-------|
| **Reader** | Subscriptions containing AVD resources |
| **Log Analytics Reader** | AVD diagnostic workspaces |

Optional data sources require additional read-only roles, each gated behind an explicit `-Include*` switch (Cost Management Reader, Reservations Reader, Intune Graph read scopes). Full matrix with setup commands: [docs/PERMISSIONS.md](docs/PERMISSIONS.md).

Use `-DryRun` to probe connectivity and permissions **without collecting any data**. Every permission failure at runtime is recorded in `permission-failures.json` with the exact missing ARM action and a remediation command.

## 6. PII Anonymization (`-ScrubPII`)

Add `-ScrubPII` to anonymize all identifiable data **in memory, before anything is written to disk**:

- VM names, host pool names, usernames (UPNs), subscription IDs, resource groups, IP addresses, ARM IDs, storage account names, and subnet names are replaced with SHA256-derived anonymous IDs.
- The salt is random per run — anonymous IDs cannot be correlated across separate collections.
- A local `*-PII-KEY.csv` mapping file is written **alongside** (not inside) the ZIP so your team can cross-reference findings. Keep the key; send only the ZIP.
- Without `-ScrubPII`, the script prints a console notice reminding you that real identifiers are in the pack.

## 7. Output Transparency & Data Retention

- The collection pack is a plain ZIP of human-readable JSON files plus a `metadata.json` manifest. **No scripts, binaries, or executable content.**
- Internal working files (checkpoints, raw ID caches, the diagnostic log) are deleted before the ZIP is created.
- Staging happens in the output folder you choose (or the current directory) — not in hidden system temp locations.
- **Inspect before sharing:** unzip, open any JSON in a text editor, redact or delete anything you're uncomfortable with, re-zip.
- **After the engagement:** delete the ZIP and the output folder. The data is a point-in-time snapshot with no ongoing purpose. Ask your consultant to confirm deletion of their copy when the engagement closes.

## 8. Verifying Your Download

Each GitHub release attaches the built `Collect-ApertureData.ps1` as an asset, and GitHub displays its **SHA-256 digest** next to the asset on the release page (click the digest to copy it).

After downloading, verify the file matches:

```powershell
(Get-FileHash .\Collect-ApertureData.ps1 -Algorithm SHA256).Hash
```

Compare the output to the `sha256:` value shown on the [release page](https://github.com/GalloTheFourth-RG/aperture-data-collector/releases/latest). If they differ, do not run the script — re-download from the official repository.

Alternatively, clone the repository and review/run the source directly — the release asset is assembled from `src/` by `build.ps1` with no external inputs.

## 9. Safe Failure Behavior

- Missing permissions or unavailable APIs produce warnings and skip that data source — the script never escalates, retries with different credentials, or prompts for elevation.
- Rate limiting (429/503) is handled with exponential backoff against the same read-only endpoints.
- The script requires PowerShell 7+ and runs under `Set-StrictMode -Version Latest`.

## 10. Reporting a Security Issue

If you find a security vulnerability in this collector, please open a [private security advisory](https://github.com/GalloTheFourth-RG/aperture-data-collector/security/advisories/new) on this repository rather than a public issue. Reports are typically acknowledged within a few business days.

---

*See also: [README — Security & Privacy](README.md#-security--privacy) · [docs/PERMISSIONS.md](docs/PERMISSIONS.md) · [docs/SCHEMA.md](docs/SCHEMA.md) (every collected field documented)*
