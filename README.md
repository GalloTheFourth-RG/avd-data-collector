# AVD Data Collector

**Open-source data collection tool for Azure Virtual Desktop environments.**

> Version 1.0.0 | June 2025

Collects ARM resource inventory, Azure Monitor metrics, and Log Analytics (KQL) query results from your AVD deployment and exports them as a portable **collection pack** (ZIP of JSON files). No analysis, no scoring, no proprietary logic — just raw data you can feed into any tooling.

---

## What It Collects

| Category | Data | Source |
|----------|------|--------|
| **Host Pools** | Configuration, load balancing, settings, registration tokens | `Get-AzWvdHostPool` |
| **Session Hosts** | Status, agent version, health, active sessions | `Get-AzWvdSessionHost` |
| **Virtual Machines** | Size, OS, zones, tags, disks, NICs, security profile, extensions | `Get-AzVM` (bulk per RG) |
| **VM Scale Sets** | VMSS config and individual instance details | `Get-AzVmss` / `Get-AzVmssVM` |
| **Application Groups** | App group types, host pool assignments | `Get-AzWvdApplicationGroup` |
| **Scaling Plans** | Autoscale definitions, schedules, pool assignments | `Get-AzResource` (ARM) |
| **Azure Monitor Metrics** | CPU, memory, disk IOPS per VM (configurable lookback) | `Get-AzMetric` |
| **Log Analytics (KQL)** | 36 pre-built queries covering connections, errors, profiles, Shortpath, agent health, and more | `Invoke-AzOperationalInsightsQuery` |
| **Capacity Reservations** | CRG utilization, allocated vs used capacity | `Invoke-AzRestMethod` (ARM REST) |
| **Quota Usage** | Per-region vCPU quota (current/limit) | `Get-AzVMUsage` |

---

## Quick Start

```powershell
# 1. Dry run — preview what will be collected
.\Collect-AVDData.ps1 `
    -TenantId "your-tenant-id" `
    -SubscriptionIds @("your-sub-id") `
    -DryRun

# 2. Full collection
.\Collect-AVDData.ps1 `
    -TenantId "your-tenant-id" `
    -SubscriptionIds @("your-sub-id") `
    -LogAnalyticsWorkspaceResourceIds @("/subscriptions/.../workspaces/your-ws")

# 3. Import into Enhanced AVD Evidence Pack (optional)
.\Get-Enhanced-AVD-EvidencePack.ps1 `
    -CollectionPack "AVD-CollectionPack-20250601-120000.zip"
```

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **PowerShell** | 7.2+ (required) |
| **Az Modules** | Az.Accounts, Az.Compute, Az.DesktopVirtualization, Az.Monitor, Az.OperationalInsights, Az.Resources |
| **Azure RBAC** | Reader on target subscriptions (minimum) |
| **Optional** | Az.Reservations for capacity reservation data |

---

## Parameters

### Required

| Parameter | Description |
|-----------|-------------|
| `-TenantId` | Azure AD / Entra ID tenant ID |
| `-SubscriptionIds` | Array of subscription IDs containing AVD resources |

### Recommended

| Parameter | Description |
|-----------|-------------|
| `-LogAnalyticsWorkspaceResourceIds` | Log Analytics workspace resource IDs for KQL queries |

### Collection Control

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-SkipAzureMonitorMetrics` | `$false` | Skip CPU/memory/disk metric collection |
| `-SkipLogAnalyticsQueries` | `$false` | Skip all KQL queries |
| `-MetricsLookbackDays` | `7` | Days of metrics history to collect (1–30) |
| `-MetricsTimeGrainMinutes` | `15` | Metric aggregation interval (5/15/30/60) |
| `-IncludeCapacityReservations` | `$false` | Collect capacity reservation group data |
| `-IncludeQuotaUsage` | `$false` | Collect per-region vCPU quota data |

### Incident Window

| Parameter | Description |
|-----------|-------------|
| `-IncludeIncidentWindow` | Collect a second set of metrics for an incident period |
| `-IncidentWindowStart` | Start of incident window (datetime) |
| `-IncidentWindowEnd` | End of incident window (datetime) |

### Operational

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-DryRun` | `$false` | Preview collection scope without running |
| `-SkipDisclaimer` | `$false` | Skip interactive disclaimer prompt |
| `-OutputPath` | Current directory | Where to write the collection pack |

---

## Output

The collector produces a ZIP file containing JSON data files:

```
AVD-CollectionPack-20250601-120000/
├── collection-metadata.json         # Schema, parameters, counts
├── host-pools.json                  # Host pool configurations
├── session-hosts.json               # Session host status & health
├── virtual-machines.json            # VM inventory with full detail
├── metrics-baseline.json            # Azure Monitor metric datapoints
├── metrics-incident.json            # Incident window metrics (if collected)
├── la-results.json                  # All KQL query results
├── scaling-plans.json               # Autoscale plan definitions
├── scaling-plan-assignments.json    # Plan-to-pool assignments
├── scaling-plan-schedules.json      # Schedule details
├── app-groups.json                  # Application groups
├── vmss.json                        # VM Scale Set configurations
├── vmss-instances.json              # VMSS instance details
├── capacity-reservation-groups.json # CRG utilization (if collected)
└── quota-usage.json                 # vCPU quota data (if collected)
```

### Schema Version

The collection pack uses schema version `1.1`, compatible with [Enhanced AVD Evidence Pack](https://github.com/intrepidtechie/enhanced-avd-evidence-pack) v4.12.0+.

---

## KQL Queries (36)

All queries are in the `queries/` directory and can be customized. Categories:

| Category | Queries |
|----------|---------|
| **Connections** | Connection summary, success rate, login time, session duration, peak/hourly concurrency |
| **Errors** | Error classification, connection errors, disconnect reasons |
| **Disconnects** | By host, heatmap, CPU correlation, reconnection loops |
| **Network** | Connection quality (RTT/bandwidth), cross-region, Shortpath usage/effectiveness/transport |
| **Performance** | Process CPU/memory, CPU percentiles per host |
| **Profiles** | Profile load performance, checkpoint login decomposition |
| **Agent Health** | Health status, version distribution, health checks |
| **Autoscale** | Autoscale activity, detailed evaluation per pool |
| **Environment** | Connection environment (OS, join type), table discovery |
| **Multi-Link** | Multi-link transport types and distribution |

---

## Collection Pack Compatibility

The output is designed as a drop-in data source for the [Enhanced AVD Evidence Pack](https://github.com/intrepidtechie/enhanced-avd-evidence-pack):

```powershell
# Collect data (this tool)
.\Collect-AVDData.ps1 -TenantId $t -SubscriptionIds $s -LogAnalyticsWorkspaceResourceIds $w

# Analyze offline (Enhanced AVD Evidence Pack)
.\Get-Enhanced-AVD-EvidencePack.ps1 -CollectionPack "AVD-CollectionPack-*.zip"
```

This separation enables workflows where:
- Someone with Azure access runs the collector
- A consultant analyzes the data offline — no Azure credentials needed
- The same pack can be re-analyzed with updated tooling
- Data can be archived for audit or comparison

---

## Runtime Estimates

| Environment | VMs | Estimated Time |
|-------------|-----|----------------|
| Small | ~50 | 3–5 min |
| Medium | ~200 | 8–15 min |
| Large | ~500 | 15–25 min |
| Very Large | ~1500+ | 30–60 min |

Metrics collection is the primary time driver. Use `-SkipAzureMonitorMetrics` for faster inventory-only runs (~2–5 min regardless of size).

---

## Security & Privacy

- **Read-only**: The collector only uses read operations — it never modifies your Azure environment
- **No external calls**: All data stays local. Nothing is sent to any external service
- **Your data**: The collection pack is plain JSON files. Inspect, filter, or redact anything before sharing

---

## Project Structure

```
avd-data-collector/
├── Collect-AVDData.ps1     # Main collector script
├── queries/                # KQL query files (customizable)
│   ├── kqlTableDiscovery.kql
│   ├── kqlWvdConnections.kql
│   ├── kqlConnectionErrors.kql
│   └── ... (36 queries)
├── docs/                   # Documentation
│   ├── QUERIES.md          # KQL query reference
│   └── SCHEMA.md           # Collection pack schema
├── examples/               # Usage examples
├── LICENSE                  # MIT License
└── CONTRIBUTING.md          # Contribution guidelines
```

---

## License

[MIT](LICENSE) — use it however you want.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. PRs welcome for new KQL queries, bug fixes, and documentation.
