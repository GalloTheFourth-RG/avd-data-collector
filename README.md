# AVD Data Collector

> **Open-source data collection for Azure Virtual Desktop**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![PowerShell 7.2+](https://img.shields.io/badge/PowerShell-7.2%2B-5391FE?logo=powershell&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-AVD-0078D4?logo=microsoftazure&logoColor=white)

Collects ARM resource inventory, Azure Monitor metrics, and Log Analytics (KQL) query results from your AVD deployment and exports them as a portable **collection pack** — a ZIP of JSON files you can feed into any tooling.

**No analysis, no scoring, no proprietary logic.** Just raw data, fully transparent.

---

## ⚡ Quick Install

Run this in PowerShell 7 to download the collector + all query files:

```powershell
irm "https://raw.githubusercontent.com/GalloTheFourth-RG/avd-data-collector/main/Install-AVDCollector.ps1" | iex
```

Or clone the repo:

```powershell
git clone https://github.com/GalloTheFourth-RG/avd-data-collector.git
cd avd-data-collector
```

---

## 🚀 Quick Start

```powershell
# Dry run — preview what will be collected (no data leaves Azure)
.\Collect-AVDData.ps1 `
    -TenantId "your-tenant-id" `
    -SubscriptionIds @("your-sub-id") `
    -DryRun

# Full collection — ARM + metrics + KQL
.\Collect-AVDData.ps1 `
    -TenantId "your-tenant-id" `
    -SubscriptionIds @("your-sub-id") `
    -LogAnalyticsWorkspaceResourceIds @(
        "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>"
    )
```

Output: `AVD-CollectionPack-YYYYMMDD-HHMMSS.zip`

---

## 📋 What It Collects

| Category | Data | API Source |
|----------|------|-----------|
| **Host Pools** | Configuration, load balancing, RDP settings | `Get-AzWvdHostPool` |
| **Session Hosts** | Status, agent version, health, active sessions | `Get-AzWvdSessionHost` |
| **Virtual Machines** | Size, OS, zones, disks, NICs, security profile, extensions | `Get-AzVM` |
| **VM Scale Sets** | VMSS config + individual instance details | `Get-AzVmss` |
| **Application Groups** | App group types, host pool assignments | `Get-AzWvdApplicationGroup` |
| **Scaling Plans** | Autoscale definitions, schedules, pool assignments | ARM API |
| **Metrics** | CPU, memory, disk IOPS per VM (configurable lookback) | `Get-AzMetric` |
| **Log Analytics** | 36 KQL queries — connections, errors, profiles, Shortpath, agent health | `Invoke-AzOperationalInsightsQuery` |
| **Capacity Reservations** | CRG utilization, allocated vs used capacity | ARM REST API |
| **Quota Usage** | Per-region vCPU quota (current / limit) | `Get-AzVMUsage` |

---

## 🔒 Security & Privacy

| Guarantee | Detail |
|-----------|--------|
| **Read-only** | Only read operations — your environment is never modified |
| **No external calls** | All data stays local. Nothing is sent to any external service |
| **Transparent** | Plain JSON output — inspect, filter, or redact anything before sharing |
| **PII Scrubbing** | Optional `-ScrubPII` flag anonymizes all identifiers before export |

### PII Scrubbing

Add `-ScrubPII` to anonymize VM names, host pool names, usernames, IPs, subscription IDs, resource groups, and ARM resource IDs. Uses SHA256 hashing with a per-run salt — same entity always maps to the same anonymous ID so correlations are preserved for analysis.

```powershell
.\Collect-AVDData.ps1 `
    -TenantId "your-tenant-id" `
    -SubscriptionIds @("your-sub-id") `
    -LogAnalyticsWorkspaceResourceIds @("/subscriptions/.../workspaces/your-ws") `
    -ScrubPII
```

---

## 📦 Requirements

| Requirement | Details |
|-------------|---------|
| **PowerShell** | 7.2+ (`pwsh.exe`, not `powershell.exe`) |
| **Az Modules** | `Az.Accounts`, `Az.Compute`, `Az.DesktopVirtualization`, `Az.Monitor`, `Az.OperationalInsights`, `Az.Resources` |
| **Azure RBAC** | **Reader** on AVD subscriptions + **Log Analytics Reader** on workspaces |

Install the Az modules if you don't have them:

```powershell
Install-Module Az.Accounts, Az.Compute, Az.DesktopVirtualization, Az.Monitor, Az.OperationalInsights, Az.Resources -Scope CurrentUser
```

---

## ⚙️ Parameters

### Required

| Parameter | Description |
|-----------|-------------|
| `-TenantId` | Azure AD / Entra ID tenant ID |
| `-SubscriptionIds` | Array of subscription IDs containing AVD resources |

### Recommended

| Parameter | Description |
|-----------|-------------|
| `-LogAnalyticsWorkspaceResourceIds` | Workspace resource IDs for KQL queries |

### Collection Control

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-SkipAzureMonitorMetrics` | `$false` | Skip CPU/memory/disk metric collection |
| `-SkipLogAnalyticsQueries` | `$false` | Skip all KQL queries |
| `-MetricsLookbackDays` | `7` | Days of metrics history (1–30) |
| `-MetricsTimeGrainMinutes` | `15` | Aggregation interval (5/15/30/60 min) |
| `-IncludeCapacityReservations` | `$false` | Collect capacity reservation group data |
| `-IncludeQuotaUsage` | `$false` | Collect per-region vCPU quota data |
| `-ScrubPII` | `$false` | Anonymize all identifiable data before export |

### Incident Window

| Parameter | Description |
|-----------|-------------|
| `-IncludeIncidentWindow` | Collect a second set of metrics for a specific incident period |
| `-IncidentWindowStart` | Start of incident window (datetime) |
| `-IncidentWindowEnd` | End of incident window (datetime) |

### Operational

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-DryRun` | `$false` | Preview collection scope without running |
| `-SkipDisclaimer` | `$false` | Skip the interactive disclaimer prompt |
| `-OutputPath` | `.` | Directory for the output collection pack |

---

## 📊 Output

The collector produces a ZIP containing JSON data files:

```
AVD-CollectionPack-20260225-120000/
├── collection-metadata.json         # Schema version, parameters, counts
├── host-pools.json                  # Host pool configurations
├── session-hosts.json               # Session host status & health
├── virtual-machines.json            # Full VM inventory
├── metrics-baseline.json            # Azure Monitor metric datapoints
├── metrics-incident.json            # Incident window metrics (if requested)
├── la-results.json                  # All KQL query results
├── scaling-plans.json               # Autoscale plan definitions
├── scaling-plan-assignments.json    # Plan-to-pool assignments
├── scaling-plan-schedules.json      # Schedule details per plan
├── app-groups.json                  # Application groups
├── vmss.json                        # VM Scale Set configurations
├── vmss-instances.json              # VMSS instance details
├── capacity-reservation-groups.json # CRG utilization (if requested)
└── quota-usage.json                 # vCPU quota (if requested)
```

---

## 🔍 KQL Queries (36)

All queries live in `queries/` and can be customized. Categories:

| Category | What It Captures |
|----------|-----------------|
| **Connections** | Summary, success rate, login time, session duration, peak & hourly concurrency |
| **Errors** | Error classification, connection failures, disconnect reasons |
| **Disconnects** | By host, heatmap, CPU correlation, reconnection loops |
| **Network** | RTT/bandwidth quality, cross-region, Shortpath usage/effectiveness/transport |
| **Performance** | Process CPU/memory consumption, CPU percentiles per host |
| **Profiles** | FSLogix profile load performance, checkpoint login decomposition |
| **Agent Health** | RD Agent status, version distribution, health check results |
| **Autoscale** | Scaling activity, detailed evaluation per host pool |
| **Environment** | Client OS, identity join type, table discovery |
| **Transport** | Multi-link transport negotiation and distribution |

---

## 🔗 Use With Enhanced AVD Evidence Pack

The collection pack is a drop-in data source for offline analysis:

```powershell
# 1. Customer runs the collector
.\Collect-AVDData.ps1 -TenantId $t -SubscriptionIds $s -LogAnalyticsWorkspaceResourceIds $w

# 2. Send the ZIP to your consultant

# 3. Consultant analyzes offline — no Azure credentials needed
.\Get-Enhanced-AVD-EvidencePack.ps1 -CollectionPack "AVD-CollectionPack-*.zip"
```

This separation enables:
- **Delegated collection** — someone with Azure access runs the collector; a consultant analyzes offline
- **Privacy control** — use `-ScrubPII` to anonymize before sharing
- **Repeatability** — re-analyze the same data with updated tooling
- **Archival** — keep collection packs for historical comparison

---

## ⏱️ Runtime Estimates

| Environment Size | VMs | Estimated Time |
|-----------------|-----|----------------|
| Small | ~50 | 3–5 min |
| Medium | ~200 | 8–15 min |
| Large | ~500 | 15–25 min |
| Very Large | 1500+ | 30–60 min |

> Metrics collection is the primary time driver. Use `-SkipAzureMonitorMetrics` for inventory-only runs (~2–5 min regardless of size).

---

## 📁 Project Structure

```
avd-data-collector/
├── Collect-AVDData.ps1        # Main collector script
├── Install-AVDCollector.ps1   # One-liner remote installer
├── queries/                   # 36 KQL query files (customizable)
│   ├── kqlTableDiscovery.kql
│   ├── kqlWvdConnections.kql
│   ├── kqlConnectionErrors.kql
│   └── ...
├── docs/                      # Documentation
│   ├── QUERIES.md
│   └── SCHEMA.md
├── examples/                  # Usage examples
├── LICENSE                    # MIT License
└── CONTRIBUTING.md
```

---

## 📜 License

[MIT](LICENSE) — use it however you want.

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome for new KQL queries, bug fixes, and docs.
