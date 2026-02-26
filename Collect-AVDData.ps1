<#
.SYNOPSIS
    AVD Data Collector — Open-source data collection for Azure Virtual Desktop
#>

# PSScriptAnalyzer disable=PSAvoidUsingWriteHost,PSAvoidUsingEmptyCatchBlock,PSUseApprovedVerbs,PSReviewUnusedParameter,PSUseBOMForUnicodeEncodedFile

<#
.DESCRIPTION
    Collects ARM resource inventory, Azure Monitor metrics, and Log Analytics (KQL)
    query results from your AVD deployment and exports them as a portable collection
    pack (ZIP of JSON files).

    The output is compatible with the Enhanced AVD Evidence Pack for offline analysis.

    Version: 1.0.0
.PARAMETER TenantId
    Azure AD / Entra ID tenant ID
.PARAMETER SubscriptionIds
    Array of subscription IDs containing AVD resources
.PARAMETER LogAnalyticsWorkspaceResourceIds
    Log Analytics workspace resource IDs for KQL queries
.PARAMETER SkipAzureMonitorMetrics
    Skip CPU/memory/disk metric collection
.PARAMETER SkipLogAnalyticsQueries
    Skip all KQL queries
.PARAMETER MetricsLookbackDays
    Days of metrics history to collect (1-30, default: 7)
.PARAMETER MetricsTimeGrainMinutes
    Metric aggregation interval in minutes (5/15/30/60, default: 15)
.PARAMETER IncludeCapacityReservations
    Collect capacity reservation group data
.PARAMETER IncludeQuotaUsage
    Collect per-region vCPU quota data
.PARAMETER IncludeIncidentWindow
    Collect a second set of metrics for an incident period
.PARAMETER IncidentWindowStart
    Start of incident window (datetime)
.PARAMETER IncidentWindowEnd
    End of incident window (datetime)
.PARAMETER ScrubPII
    Anonymize all identifiable data (VM names, host pool names, usernames,
    subscription IDs, IPs, resource groups) before export. Same entity always
    maps to the same anonymous ID within a run.
.PARAMETER DryRun
    Preview collection scope without running
.PARAMETER SkipDisclaimer
    Skip interactive disclaimer prompt
.PARAMETER OutputPath
    Directory to write the collection pack (default: current directory)
#>
param(
    # Initialize script-scoped variables
    
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    [Parameter(Mandatory = $true)]
    [string[]]$SubscriptionIds,
    [string[]]$LogAnalyticsWorkspaceResourceIds = @(),
    [switch]$SkipAzureMonitorMetrics,
    [switch]$SkipLogAnalyticsQueries,
    [ValidateRange(1, 30)]
    [int]$MetricsLookbackDays = 7,
    [ValidateSet(5, 15, 30, 60)]
    [int]$MetricsTimeGrainMinutes = 15,
    [switch]$IncludeCapacityReservations,
    [switch]$IncludeQuotaUsage,
    [switch]$IncludeIncidentWindow,
    [datetime]$IncidentWindowStart = (Get-Date).AddDays(-14),
    [datetime]$IncidentWindowEnd = (Get-Date),
    [switch]$ScrubPII,
    [switch]$DryRun,
    [switch]$SkipDisclaimer,
    [int]$MetricsParallel = 15,
    [int]$KqlParallel     = 5,
    [string]$OutputPath = "."
)  # MetricsParallel and KqlParallel control ForEach-Object throttling (default 15,5)

# Initialize script-scoped variables
$script:currentSubContext = $null

# Ensure Write-Step is defined before any usage
function Write-Step {
    param([string]$Step, [string]$Message, [string]$Status = "Start")
    $prefix = switch ($Status) {
        "Start"    { "  " }
        "Progress" { "    " }
        "Done"     { "  [OK] " }
        "Skip"     { "  [SKIP] " }
        "Warn"     { "  [WARN] " }
        "Error"    { "  [ERR] " }
    }
    $color = switch ($Status) {
        "Start"    { "Cyan" }
        "Progress" { "Gray" }
        "Done"     { "Green" }
        "Skip"     { "Yellow" }
        "Warn"     { "Yellow" }
        "Error"    { "Red" }
    }
    if ($Status -eq "Progress") {
        Write-Host "${prefix}${Message}" -ForegroundColor $color
    } else {
        Write-Host "${prefix}${Step} - ${Message}" -ForegroundColor $color
    }
}

# Ensure SafeCount is defined before any usage
if (-not (Get-Command SafeCount -ErrorAction SilentlyContinue)) {
    function SafeCount {
        param([object]$Obj)
        if ($null -eq $Obj) { return 0 }
        if ($Obj -is [System.Collections.ICollection]) { return $Obj.Count }
        return @($Obj).Count
    }
}

# helper to retry Az calls on throttling or transient errors
function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)] [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 4
    )
    $attempt = 0
    while ($true) {
        try {
            return & $ScriptBlock
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -match '429|throttl|503' -and $attempt -lt $MaxAttempts) {
                $attempt++
                $delay = [math]::Pow(2, $attempt) * 5
                Write-Host "    Throttled or transient error, retrying in $delay seconds (attempt $attempt)" -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
                continue
            }
            throw
        }
    }
}

# Ensure SafeArray is available before first usage
if (-not (Get-Command SafeArray -ErrorAction SilentlyContinue)) {
    function SafeArray {
        param([object]$Obj)
        if ($null -eq $Obj) { return @() }
        return @($Obj)
    }
}

# Ensure SafeProp and SafeArmProp are available early (used during ARM collection)
if (-not (Get-Command SafeProp -ErrorAction SilentlyContinue)) {
    function SafeProp {
        param([object]$Obj, [string]$Name)
        if ($null -eq $Obj) { return $null }
        if ($Obj.PSObject.Properties.Name -contains $Name) { return $Obj.$Name }
        return $null
    }
}

if (-not (Get-Command SafeArmProp -ErrorAction SilentlyContinue)) {
    function SafeArmProp {
        param([object]$Obj, [string]$Name)
        if ($null -eq $Obj) { return $null }
        if ($Obj.PSObject.Properties.Name -contains $Name) { return $Obj.$Name }
        if ($Obj.PSObject.Properties.Name -contains 'Properties') {
            $p = $Obj.Properties
            if ($null -ne $p -and $p.PSObject.Properties.Name -contains $Name) { return $p.$Name }
        }
        if ($Obj.PSObject.Properties.Name -contains 'ResourceProperties') {
            $rp = $Obj.ResourceProperties
            if ($null -ne $rp -and $rp.PSObject.Properties.Name -contains $Name) { return $rp.$Name }
        }
        return $null
    }
}

# Provide Get-ArmIdSafe early for callers in Step 1
if (-not (Get-Command Get-ArmIdSafe -ErrorAction SilentlyContinue)) {
    function Get-ArmIdSafe {
        param([object]$Obj)
        if ($null -eq $Obj) { return "" }
        if ($Obj.PSObject.Properties.Name -contains 'Id') { return $Obj.Id }
        if ($Obj.PSObject.Properties.Name -contains 'ResourceId') { return $Obj.ResourceId }
        return ""
    }
}

if (-not (Get-Command Get-NameFromArmId -ErrorAction SilentlyContinue)) {
    function Get-NameFromArmId {
        param([string]$ArmId)
        if ([string]::IsNullOrEmpty($ArmId)) { return "" }
        $parts = $ArmId -split '/'
        if ($parts.Count -ge 1) { return $parts[-1] }
        return ""
    }
}

if (-not (Get-Command Get-SubFromArmId -ErrorAction SilentlyContinue)) {
    function Get-SubFromArmId {
        param([string]$ArmId)
        if ([string]::IsNullOrEmpty($ArmId)) { return "" }
        $parts = $ArmId -split '/'
        if ($parts.Count -ge 3) { return $parts[2] }
        return ""
    }
}

$WarningPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$script:ScriptVersion = "1.0.0"
$script:SchemaVersion = "1.1"

# Initialize main collection containers
$hostPools = [System.Collections.Generic.List[object]]::new()
$sessionHosts = [System.Collections.Generic.List[object]]::new()
$vms = [System.Collections.Generic.List[object]]::new()
$vmss = [System.Collections.Generic.List[object]]::new()
$vmssInstances = [System.Collections.Generic.List[object]]::new()
$appGroups = [System.Collections.Generic.List[object]]::new()
$scalingPlans = [System.Collections.Generic.List[object]]::new()
$scalingPlanAssignments = [System.Collections.Generic.List[object]]::new()
$scalingPlanSchedules = [System.Collections.Generic.List[object]]::new()
$vmMetrics = [System.Collections.Generic.List[object]]::new()
$vmMetricsIncident = [System.Collections.Generic.List[object]]::new()
$laResults = [System.Collections.Generic.List[object]]::new()
$capacityReservationGroups = [System.Collections.Generic.List[object]]::new()
$quotaUsage = [System.Collections.Generic.List[object]]::new()

# Misc helpers / caches
$vmMetrics = $vmMetrics

# =========================================================
# PowerShell 7 Requirement
# =========================================================
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host ""
    Write-Host "ERROR: PowerShell 7.2+ is required." -ForegroundColor Red
    Write-Host ""
    Write-Host "You are running PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Install PowerShell 7:" -ForegroundColor Cyan
    Write-Host "  winget install Microsoft.PowerShell" -ForegroundColor White
    Write-Host "  or: https://aka.ms/powershell-release?tag=stable" -ForegroundColor White
    Write-Host ""
    Write-Host "Then run this script from pwsh.exe (not powershell.exe)" -ForegroundColor Cyan
    exit 1
}

# =========================================================
# PII Scrubbing
# =========================================================
$script:piiSalt = [guid]::NewGuid().ToString().Substring(0, 8)
$script:piiCache = @{}

function Protect-Value {
    param([string]$Value, [string]$Prefix = "Anon", [int]$Length = 4)
    if (-not $ScrubPII) { return $Value }
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    $key = "${Prefix}:${Value}"
    if ($script:piiCache.ContainsKey($key)) { return $script:piiCache[$key] }
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes("${Value}:${script:piiSalt}")
    )
    $short = [BitConverter]::ToString($hash[0..($Length/2)]).Replace('-','').Substring(0, $Length).ToUpper()
    $result = "${Prefix}-${short}"
    $script:piiCache[$key] = $result
    return $result
}

function Protect-SubscriptionId {
    param([string]$Value)
    if (-not $ScrubPII) { return $Value }
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    if ($Value.Length -ge 4) { return "****-****-****-" + $Value.Substring($Value.Length - 4) }
    return "****"
}

function Protect-VMName       { param([string]$Value); return (Protect-Value -Value $Value -Prefix "Host" -Length 6) }
function Protect-HostPoolName { param([string]$Value); return (Protect-Value -Value $Value -Prefix "Pool" -Length 4) }
function Protect-ResourceGroup { param([string]$Value); return (Protect-Value -Value $Value -Prefix "RG" -Length 4) }
function Protect-Username     { param([string]$Value); return (Protect-Value -Value $Value -Prefix "User" -Length 4) }
function Protect-IP {
    param([string]$Value)
    if (-not $ScrubPII) { return $Value }
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    if ($Value -match '^(\d+\.\d+\.\d+)\.\d+$') { return "$($matches[1]).x" }
    return "x.x.x.x"
}
function Protect-ArmId {
    param([string]$Value)
    if (-not $ScrubPII) { return $Value }
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    return (Protect-Value -Value $Value -Prefix "ArmId" -Length 8)
}
function Protect-SubnetId {
    param([string]$Value)
    if (-not $ScrubPII) { return $Value }
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    return (Protect-Value -Value $Value -Prefix "Subnet" -Length 6)
}

function Protect-KqlRow {
    param([PSCustomObject]$Row)
    if (-not $ScrubPII) { return $Row }
    foreach ($p in @($Row.PSObject.Properties)) {
        if ($null -eq $p.Value -or $p.Value -eq '') { continue }
        $val = [string]$p.Value
        switch -Regex ($p.Name) {
            '^(UserName|UserPrincipalName|UserId|User|UserDisplayName|ActiveDirectoryUserName)$' {
                $Row.$($p.Name) = Protect-Username $val; break
            }
            '^(SessionHostName|_ResourceId|Computer|ComputerName|ResourceId)$' {
                $Row.$($p.Name) = Protect-VMName $val; break
            }
            '^(ClientIP|ClientPublicIP|SourceIP|PrivateIP)$' {
                $Row.$($p.Name) = Protect-IP $val; break
            }
            '^(SubscriptionId|subscriptionId)$' {
                $Row.$($p.Name) = Protect-SubscriptionId $val; break
            }
            '^(HostPool|HostPoolName)$' {
                $Row.$($p.Name) = Protect-HostPoolName $val; break
            }
            '^(ResourceGroup|ResourceGroupName)$' {
                $Row.$($p.Name) = Protect-ResourceGroup $val; break
            }
        }
    }
    return $Row

# =========================================================
# Helpers
# =========================================================
## SafeArray is defined earlier to ensure availability before usage

function SafeCount {
    param([object]$Obj)
    if ($null -eq $Obj) { return 0 }
    if ($Obj -is [System.Collections.ICollection]) { return $Obj.Count }
    return @($Obj).Count
}

function SafeProp {
    param([object]$Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj.PSObject.Properties.Name -contains $Name) { return $Obj.$Name }
    return $null
}

function SafeArmProp {
    param([object]$Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    # Az module v3: top-level
    if ($Obj.PSObject.Properties.Name -contains $Name) { return $Obj.$Name }
    # Az module v4+: nested under .Properties
    if ($Obj.PSObject.Properties.Name -contains 'Properties') {
        $p = $Obj.Properties
        if ($null -ne $p -and $p.PSObject.Properties.Name -contains $Name) { return $p.$Name }
    }
    # Az module v4+: nested under .ResourceProperties
    if ($Obj.PSObject.Properties.Name -contains 'ResourceProperties') {
        $rp = $Obj.ResourceProperties
        if ($null -ne $rp -and $rp.PSObject.Properties.Name -contains $Name) { return $rp.$Name }
    }
    return $null
}

function Get-SubFromArmId {
    param([string]$ArmId)
    if ([string]::IsNullOrEmpty($ArmId)) { return "" }
    $parts = $ArmId -split '/'
    if ($parts.Count -ge 3) { return $parts[2] }
    return ""
}

function Get-NameFromArmId {
    param([string]$ArmId)
    if ([string]::IsNullOrEmpty($ArmId)) { return "" }
    $parts = $ArmId -split '/'
    if ($parts.Count -ge 1) { return $parts[-1] }
    return ""
}

function Get-ArmIdSafe {
    param([object]$Obj)
    if ($null -eq $Obj) { return "" }
    if ($Obj.PSObject.Properties.Name -contains 'Id') { return $Obj.Id }
    if ($Obj.PSObject.Properties.Name -contains 'ResourceId') { return $Obj.ResourceId }
    return ""
}

function Write-Step {
    param([string]$Step, [string]$Message, [string]$Status = "Start")
    $prefix = switch ($Status) {
        "Start"    { "  " }
        "Progress" { "    " }
        "Done"     { "  [OK] " }
        "Skip"     { "  [SKIP] " }
        "Warn"     { "  [WARN] " }
        "Error"    { "  [ERR] " }
    }
    $color = switch ($Status) {
        "Start"    { "Cyan" }
        "Progress" { "Gray" }
        "Done"     { "Green" }
        "Skip"     { "Yellow" }
        "Warn"     { "Yellow" }
        "Error"    { "Red" }
    }
    if ($Status -eq "Progress") {
        Write-Host "${prefix}${Message}" -ForegroundColor $color
    } else {
        Write-Host "${prefix}${Step} - ${Message}" -ForegroundColor $color
    }
}

# =========================================================
# Prerequisite Validation
# =========================================================
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                                       ║" -ForegroundColor Cyan
Write-Host "║              AVD Data Collector — v$($script:ScriptVersion)                            ║" -ForegroundColor Cyan
Write-Host "║              Open-Source Data Collection for Azure Virtual Desktop    ║" -ForegroundColor Cyan
Write-Host "║                                                                       ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-Host "Validating prerequisites..." -ForegroundColor Cyan

$requiredModules = @(
    @{Name = 'Az.Accounts';              MinVersion = '2.0.0' },
    @{Name = 'Az.Compute';               MinVersion = '4.0.0' },
    @{Name = 'Az.DesktopVirtualization';  MinVersion = '2.0.0' },
    @{Name = 'Az.Monitor';               MinVersion = '2.0.0' },
    @{Name = 'Az.OperationalInsights';    MinVersion = '2.0.0' },
    @{Name = 'Az.Resources';             MinVersion = '4.0.0' }
)

$missingModules = @()
foreach ($module in $requiredModules) {
    $installed = Get-Module -ListAvailable -Name $module.Name |
        Where-Object { $_.Version -ge [version]$module.MinVersion } |
        Select-Object -First 1

    if (-not $installed) {
        $missingModules += $module.Name
        Write-Host "  ✗ Missing: $($module.Name) (>= $($module.MinVersion))" -ForegroundColor Red
    }
    else {
        Write-Host "  ✓ Found: $($module.Name) v$($installed.Version)" -ForegroundColor Green
    }
}
    $totalSteps = if ($SkipLogAnalyticsQueries) { 3 } else { 4 }
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  Step 2 of $totalSteps`: Collecting Log Analytics Perf Metrics" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host ""

    # Build VM name list for Log Analytics perf queries.
    # Use the raw (unscrubbed) VM names when available so queries match the 'Computer' field.
    if (Get-Variable -Name rawVmNames -Scope Script -ErrorAction SilentlyContinue -and (SafeCount $rawVmNames) -gt 0) {
        $vmNames = @($rawVmNames | Select-Object -Unique)
    }
    elseif (SafeCount $vms -gt 0) {
        # vms may contain protected/anonymized names when -ScrubPII is used; only use when no raw names present
        $vmNames = @($vms | Where-Object { $_.VMName } | Select-Object -ExpandProperty VMName -Unique)
    }
    else {
        $vmNames = @()
    }
    $metricsEnd   = Get-Date
    $metricsStart = $metricsEnd.AddDays(-$MetricsLookbackDays)
    $grain = $MetricsTimeGrainMinutes

    Write-Host "  Collecting Perf metrics for $(SafeCount $vmNames) VMs ($MetricsLookbackDays-day lookback, ${MetricsTimeGrainMinutes}m grain)" -ForegroundColor Gray
    Write-Host ""

    $metricsCollected = [System.Collections.Generic.List[object]]::new()
    $metricsTotal = SafeCount $vmNames

    foreach ($wsId in $LogAnalyticsWorkspaceResourceIds) {
        $parts = $wsId.TrimEnd('/') -split '/'
        $resourceGroupName = $parts[4]
        $workspaceName     = $parts[8]
        $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroupName -Name $workspaceName -ErrorAction Stop
        $workspaceId = $workspace.CustomerId

        foreach ($vmName in $vmNames) {
            $kql = @"
Perf
| where Computer == '$vmName'
| where TimeGenerated between (datetime($metricsStart) .. datetime($metricsEnd))
| where (ObjectName == 'Processor' and CounterName == '% Processor Time' and InstanceName == '_Total')
   or (ObjectName == 'Memory' and CounterName == 'Available MBytes')
| summarize AvgValue=avg(CounterValue), MaxValue=max(CounterValue) by Computer, ObjectName, CounterName, bin(TimeGenerated, ${grain}m)
| order by TimeGenerated asc
"@
            $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $kql -ErrorAction Stop
            if ($result.Results) {
                foreach ($row in $result.Results) {
                    $metric = if ($row.ObjectName -eq 'Processor') { 'Percentage CPU' } elseif ($row.ObjectName -eq 'Memory') { 'Available Memory Bytes' } else { $row.CounterName }
                    $metricsCollected.Add([PSCustomObject]@{
                        VmName      = $row.Computer
                        Metric      = $metric
                        Aggregation = 'Average'
                        TimeStamp   = $row.TimeGenerated
                        Value       = if ($metric -eq 'Available Memory Bytes') { $row.AvgValue * 1MB } else { $row.AvgValue }
                    })
                    $metricsCollected.Add([PSCustomObject]@{
                        VmName      = $row.Computer
                        Metric      = $metric
                        Aggregation = 'Maximum'
                        TimeStamp   = $row.TimeGenerated
                        Value       = if ($metric -eq 'Available Memory Bytes') { $row.MaxValue * 1MB } else { $row.MaxValue }
                    })
                }
            }
        }
    }

    foreach ($item in $metricsCollected) {
        if ($ScrubPII) { $item.VmName = Protect-VMName $item.VmName }
        $vmMetrics.Add($item)
    }

    Write-Host "  ✓ Metrics collected: $(SafeCount $vmMetrics) datapoints for $metricsTotal VMs" -ForegroundColor Green
    Write-Host ""

    # ── Incident Window Metrics (optional) ──
    if ($IncludeIncidentWindow) {
        Write-Host "  Collecting incident window Perf metrics ($IncidentWindowStart → $IncidentWindowEnd)..." -ForegroundColor Cyan

        $incidentCollected = [System.Collections.Generic.List[object]]::new()

        foreach ($wsId in $LogAnalyticsWorkspaceResourceIds) {
            $parts = $wsId.TrimEnd('/') -split '/'
            $resourceGroupName = $parts[4]
            $workspaceName     = $parts[8]
            $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroupName -Name $workspaceName -ErrorAction Stop
            $workspaceId = $workspace.CustomerId

            foreach ($vmName in $vmNames) {
                $kql = @"
Perf
| where Computer == '$vmName'
| where TimeGenerated between (datetime($IncidentWindowStart) .. datetime($IncidentWindowEnd))
| where (ObjectName == 'Processor' and CounterName == '% Processor Time' and InstanceName == '_Total')
   or (ObjectName == 'Memory' and CounterName == 'Available MBytes')
| summarize AvgValue=avg(CounterValue), MaxValue=max(CounterValue) by Computer, ObjectName, CounterName, bin(TimeGenerated, ${grain}m)
| order by TimeGenerated asc
"@
                $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $kql -ErrorAction Stop
                if ($result.Results) {
                    foreach ($row in $result.Results) {
                        $metric = if ($row.ObjectName -eq 'Processor') { 'Percentage CPU' } elseif ($row.ObjectName -eq 'Memory') { 'Available Memory Bytes' } else { $row.CounterName }
                        $incidentCollected.Add([PSCustomObject]@{
                            VmName      = $row.Computer
                            Metric      = $metric
                            Aggregation = 'Average'
                            TimeStamp   = $row.TimeGenerated
                            Value       = if ($metric -eq 'Available Memory Bytes') { $row.AvgValue * 1MB } else { $row.AvgValue }
                        })
                        $incidentCollected.Add([PSCustomObject]@{
                            VmName      = $row.Computer
                            Metric      = $metric
                            Aggregation = 'Maximum'
                            TimeStamp   = $row.TimeGenerated
                            Value       = if ($metric -eq 'Available Memory Bytes') { $row.MaxValue * 1MB } else { $row.MaxValue }
                        })
                    }
                }
            }
        }

        foreach ($item in $incidentCollected) {
            if ($ScrubPII) { $item.VmName = Protect-VMName $item.VmName }
            $vmMetricsIncident.Add($item)
        }
        Write-Host "  ✓ Incident window metrics collected: $(SafeCount $vmMetricsIncident) datapoints" -ForegroundColor Green
        Write-Host ""
    }
}

# Raw VM ARM IDs for metrics collection (unaffected by PII scrubbing)
$rawVmIds               = [System.Collections.Generic.List[string]]::new()
# Raw VM names for Log Analytics perf queries (unaffected by PII scrubbing)
$rawVmNames             = [System.Collections.Generic.List[string]]::new()

# NIC cache: batch-fetch per RG
$nicCacheByRg = @{}

# VM cache: bulk-fetch per RG for O(n/rg) instead of O(n) API calls
$vmCacheByRg = @{}
$vmStatusCacheByRg = @{}
$vmCacheByName = @{}

# Disk encryption cache
$script:diskEncCache = @{}

# Timing
$script:collectionStart = Get-Date

# Output folder (create early so exports work)
try {
    $timeStamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $outFolderName = "AVD-CollectionPack-$timeStamp"
    $baseOut = if ($OutputPath) { (Resolve-Path -Path $OutputPath).Path } else { (Get-Location).Path }
    $outFolder = Join-Path $baseOut $outFolderName
    if (-not (Test-Path $outFolder)) { New-Item -Path $outFolder -ItemType Directory -Force | Out-Null }
    # start diagnostic transcript
    $diagPath = Join-Path $outFolder 'diagnostic.log'
    if (Get-Module -ListAvailable -Name Microsoft.PowerShell.Utility) {
        Start-Transcript -Path $diagPath -Force | Out-Null
    }
}
catch {
    $outFolder = Join-Path (Get-Location).Path "AVD-CollectionPack-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
    if (-not (Test-Path $outFolder)) { New-Item -Path $outFolder -ItemType Directory -Force | Out-Null }
}

# =========================================================
# KQL Query Loading
# =========================================================
$queriesDir = Join-Path $PSScriptRoot "queries"
$kqlQueries = @{}
if (Test-Path $queriesDir) {
    Get-ChildItem -Path $queriesDir -Filter "*.kql" | ForEach-Object {
        $varName = $_.BaseName
        $kqlQueries[$varName] = Get-Content $_.FullName -Raw
    }
    Write-Host "Loaded $($kqlQueries.Count) KQL queries from queries/" -ForegroundColor Gray
}
else {
    Write-Host "  ⚠ queries/ directory not found — KQL queries will be skipped" -ForegroundColor Yellow
    $SkipLogAnalyticsQueries = $true
}

# =========================================================
# Log Analytics Query Function
# =========================================================
function Invoke-LaQuery {
    param(
        [string]$WorkspaceResourceId,
        [string]$Label,
        [string]$Query,
        [datetime]$StartTime,
        [datetime]$EndTime
    )

    if (-not $WorkspaceResourceId -or ($WorkspaceResourceId -split '/').Count -lt 9) {
        return [PSCustomObject]@{
            WorkspaceResourceId = $WorkspaceResourceId
            Label               = $Label
            QueryName           = "Meta"
            Status              = "InvalidWorkspaceId"
            Error               = "Workspace resource ID is missing or malformed."
            RowCount            = 0
        }
    }

    $parts = $WorkspaceResourceId.TrimEnd('/') -split '/'
    $resourceGroupName = $parts[4]
    $workspaceName     = $parts[8]

    if (-not $resourceGroupName -or -not $workspaceName) {
        return [PSCustomObject]@{
            WorkspaceResourceId = $WorkspaceResourceId
            Label               = $Label
            QueryName           = "Meta"
            Status              = "InvalidWorkspaceId"
            Error               = "Could not extract RG or workspace name from ID: $WorkspaceResourceId"
            RowCount            = 0
        }
    }

    try {
        $workspace = Get-AzOperationalInsightsWorkspace `
            -ResourceGroupName $resourceGroupName `
            -Name $workspaceName `
            -ErrorAction Stop
    }
    catch {
        return [PSCustomObject]@{
            WorkspaceResourceId = $WorkspaceResourceId
            Label               = $Label
            QueryName           = "Meta"
            Status              = "WorkspaceNotFound"
            RowCount            = 0
        }
    }

    $duration = New-TimeSpan -Start $StartTime -End $EndTime

    try {
        $result = Invoke-AzOperationalInsightsQuery `
            -WorkspaceId $workspace.CustomerId `
            -Query $Query `
            -Timespan $duration `
            -ErrorAction Stop
    }
    catch {
        return [PSCustomObject]@{
            WorkspaceResourceId = $WorkspaceResourceId
            Label               = $Label
            QueryName           = "Meta"
            Status              = "QueryFailed"
            Error               = $_.Exception.Message
            RowCount            = 0
        }
    }

    if (-not $result.Results -or @($result.Results).Count -eq 0) {
        return [PSCustomObject]@{
            WorkspaceResourceId = $WorkspaceResourceId
            Label               = $Label
            QueryName           = "Meta"
            Status              = "NoRowsReturned"
            RowCount            = 0
        }
    }

    $output = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $result.Results) {
        $o = [PSCustomObject]@{
            WorkspaceResourceId = $WorkspaceResourceId
            Label               = $Label
            QueryName           = "AVD"
        }
        foreach ($p in $row.PSObject.Properties) {
            Add-Member -InputObject $o -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force
        }
        $output.Add($o)
    }

    return $output
}

# =========================================================
# Scaling Plan Collection Functions
# =========================================================
function Expand-ScalingPlanEvidence {
    param([object]$PlanResource, [string]$SubId)

    if (-not $PlanResource) { return }

    $planId = if ($PlanResource.PSObject.Properties.Name -contains 'ResourceId') { $PlanResource.ResourceId } else { Get-ArmIdSafe $PlanResource }
    $rg     = $PlanResource.ResourceGroupName
    $name   = $PlanResource.Name
    $loc    = $PlanResource.Location
    $props  = $PlanResource.Properties

    $scalingPlans.Add([PSCustomObject]@{
        SubscriptionId  = Protect-SubscriptionId $SubId
        ResourceGroup   = Protect-ResourceGroup $rg
        ScalingPlanName = Protect-Value -Value $name -Prefix "SPlan" -Length 4
        Location        = $loc
        TimeZone        = SafeProp $props 'timeZone'
        HostPoolType    = SafeProp $props 'hostPoolType'
        Description     = $(if ($ScrubPII) { '[SCRUBBED]' } else { SafeProp $props 'description' })
        FriendlyName    = $(if ($ScrubPII) { '[SCRUBBED]' } else { SafeProp $props 'friendlyName' })
        ExclusionTag    = SafeProp $props 'exclusionTag'
        Id              = Protect-ArmId $planId
    })

    foreach ($hpr in SafeArray $props.hostPoolReferences) {
        $hpArmId = SafeProp $hpr 'hostPoolArmPath'
        $scalingPlanAssignments.Add([PSCustomObject]@{
            SubscriptionId      = Protect-SubscriptionId $SubId
            ResourceGroup       = Protect-ResourceGroup $rg
            ScalingPlanName     = Protect-Value -Value $name -Prefix "SPlan" -Length 4
            ScalingPlanId       = Protect-ArmId $planId
            HostPoolArmId       = Protect-ArmId $hpArmId
            HostPoolName        = Protect-HostPoolName (Get-NameFromArmId $hpArmId)
            IsEnabled           = SafeProp $hpr 'scalingPlanEnabled'
        })
    }

    foreach ($sch in SafeArray $props.schedules) {
        $scalingPlanSchedules.Add([PSCustomObject]@{
            SubscriptionId        = Protect-SubscriptionId $SubId
            ResourceGroup         = Protect-ResourceGroup $rg
            ScalingPlanName       = Protect-Value -Value $name -Prefix "SPlan" -Length 4
            ScalingPlanId         = Protect-ArmId $planId
            ScheduleName          = SafeProp $sch 'name'
            DaysOfWeek            = ((SafeArray (SafeProp $sch 'daysOfWeek')) -join ",")
            RampUpStartTime       = SafeProp $sch 'rampUpStartTime'
            PeakStartTime         = SafeProp $sch 'peakStartTime'
            RampDownStartTime     = SafeProp $sch 'rampDownStartTime'
            OffPeakStartTime      = SafeProp $sch 'offPeakStartTime'
            RampUpCapacity        = SafeProp $sch 'rampUpCapacityThresholdPct'
            RampUpMinHostsPct     = SafeProp $sch 'rampUpMinimumHostsPct'
            PeakLoadBalancing     = SafeProp $sch 'peakLoadBalancingAlgorithm'
            RampDownCapacity      = SafeProp $sch 'rampDownCapacityThresholdPct'
            RampDownMinHostsPct   = SafeProp $sch 'rampDownMinimumHostsPct'
            OffPeakLoadBalancing  = SafeProp $sch 'offPeakLoadBalancingAlgorithm'
            OffPeakMinHostsPct    = SafeProp $sch 'offPeakMinimumHostsPct'
            RampDownForceLogoff   = SafeProp $sch 'rampDownForceLogoffUsers'
            RampDownLogoffTimeout = SafeProp $sch 'rampDownWaitTimeMinutes'
            RampDownNotification  = $(if ($ScrubPII) { '[SCRUBBED]' } else { SafeProp $sch 'rampDownNotificationMessage' })
        })
    }
}

# =========================================================
# STEP 1: Collect ARM Resources
# =========================================================
Write-Host ""
if ($ScrubPII) {
    Write-Host "  [PII SCRUBBING ENABLED] identifiers will be anonymized" -ForegroundColor Magenta
    Write-Host ""
}
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Step 1 of $(if ($SkipAzureMonitorMetrics) { '3' } else { '4' }): Collecting ARM Resources" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

$subsProcessed = 0
$subsSkipped = @()

foreach ($subId in $SubscriptionIds) {
    try {
        $subsProcessed++
        Write-Step -Step "Subscription $subsProcessed/$(SafeCount $SubscriptionIds)" -Message $subId

        # Skip Set-AzContext if we already validated context for this subscription during auth
        if ($script:currentSubContext -ne $subId) {
            try {
                Invoke-WithRetry { Set-AzContext -SubscriptionId $subId -TenantId $TenantId -ErrorAction Stop | Out-Null }
                $script:currentSubContext = $subId
            }
            catch {
                $errMsg = $_.Exception.Message
                Write-Step -Step "Subscription" -Message "Cannot access $subId" -Status "Error"
                if ($errMsg -match 'interaction is required|multi-factor|MFA|conditional access') {
                    Write-Host "    Token expired or MFA required. Run: Connect-AzAccount -TenantId '$TenantId'" -ForegroundColor Yellow
                } elseif ($errMsg -match 'not found|does not exist|invalid') {
                    Write-Host "    Subscription not found in tenant. Verify the subscription ID is correct." -ForegroundColor Yellow
                } else {
                    Write-Host "    $errMsg" -ForegroundColor Gray
                }
                $subsSkipped += $subId
                continue
            }
        }

        # ── Host Pools ──
        Write-Step -Step "Host Pools" -Message "Enumerating..." -Status "Progress"
    }
    catch {
        Write-Step -Step "Subscription" -Message "Unexpected error processing ${subId}: $($_.Exception.Message)" -Status "Error"
        continue
    }
    $hpObjs = Get-AzWvdHostPool -ErrorAction SilentlyContinue
    if ((SafeCount $hpObjs) -eq 0) {
        Write-Step -Step "Host Pools" -Message "No host pools found in this subscription" -Status "Warn"
    }

    # ── Bulk VM Pre-Fetch (per RG) ──
    # Collect unique RGs from host pools, batch-fetch VMs
    $hpResourceGroups = @()
    foreach ($hp in SafeArray $hpObjs) {
        $hpId = SafeArmProp $hp 'Id'
        if (-not $hpId) { $hpId = Get-ArmIdSafe $hp }
        if ($hpId) {
            $rgName = ($hpId -split '/')[4]
            if ($rgName -and $rgName -notin $hpResourceGroups) {
                $hpResourceGroups += $rgName
            }
        }
    }

    foreach ($bulkRg in $hpResourceGroups) {
        if (-not $vmCacheByRg.ContainsKey($bulkRg)) {
            try {
                Write-Step -Step "VM Cache" -Message "Bulk-fetching VMs in RG: $bulkRg" -Status "Progress"
                $rgVmModels = @(Get-AzVM -ResourceGroupName $bulkRg -ErrorAction SilentlyContinue)
                $rgVmStatuses = @(Get-AzVM -ResourceGroupName $bulkRg -Status -ErrorAction SilentlyContinue)

                $vmCacheByRg[$bulkRg] = @{}
                $vmStatusCacheByRg[$bulkRg] = @{}

                foreach ($v in $rgVmModels) {
                    $vmCacheByRg[$bulkRg][$v.Name] = $v
                    $vmCacheByName[$v.Name] = $v
                }
                foreach ($v in $rgVmStatuses) {
                    $vmStatusCacheByRg[$bulkRg][$v.Name] = $v
                }
            }
            catch {
                Write-Step -Step "VM Cache" -Message "Failed to pre-fetch RG $bulkRg — $($_.Exception.Message)" -Status "Warn"
            }
        }
    }

    # ── Process Host Pools ──
    foreach ($hp in SafeArray $hpObjs) {
        $hpName = SafeArmProp $hp 'Name'
        if (-not $hpName) { $hpName = $hp.Name }
        $hpId = SafeArmProp $hp 'Id'
        if (-not $hpId) { $hpId = Get-ArmIdSafe $hp }
        $hpRg = if ($hpId) { ($hpId -split '/')[4] } else { "" }

        $hostPools.Add([PSCustomObject]@{
            SubscriptionId       = Protect-SubscriptionId $subId
            ResourceGroup        = Protect-ResourceGroup $hpRg
            HostPoolName         = Protect-HostPoolName $hpName
            HostPoolType         = SafeArmProp $hp 'HostPoolType'
            LoadBalancer         = SafeArmProp $hp 'LoadBalancerType'
            MaxSessions          = SafeArmProp $hp 'MaxSessionLimit'
            StartVMOnConnect     = SafeArmProp $hp 'StartVMOnConnect'
            PreferredAppGroupType = SafeArmProp $hp 'PreferredAppGroupType'
            Location             = $hp.Location
            ValidationEnv        = SafeArmProp $hp 'ValidationEnvironment'
            CustomRdpProperty    = $(if ($ScrubPII) { '[SCRUBBED]' } else { SafeArmProp $hp 'CustomRdpProperty' })
            Id                   = Protect-ArmId $hpId
        })

        # Session Hosts
        Write-Step -Step "Session Hosts" -Message "$hpName" -Status "Progress"
        $shObjs = @()
        try {
            $shObjs = @(Get-AzWvdSessionHost -ResourceGroupName $hpRg -HostPoolName $hpName -ErrorAction SilentlyContinue)
        }
        catch {
            Write-Step -Step "Session Hosts" -Message "Failed for $hpName — $($_.Exception.Message)" -Status "Warn"
        }

        foreach ($sh in $shObjs) {
            $shName = SafeArmProp $sh 'Name'
            if (-not $shName) { $shName = $sh.Name }
            # Session host name format: hostpool/vmname.domain.com
            $shSimpleName = if ($shName -match '/') { ($shName -split '/')[-1] } else { $shName }
            $vmName = ($shSimpleName -split '\.')[0]

            $sessionHosts.Add([PSCustomObject]@{
                SubscriptionId    = Protect-SubscriptionId $subId
                ResourceGroup     = Protect-ResourceGroup $hpRg
                HostPoolName      = Protect-HostPoolName $hpName
                SessionHostName   = Protect-VMName $shSimpleName
                SessionHostArmName = Protect-ArmId $shName
                Status            = SafeArmProp $sh 'Status'
                AllowNewSession   = SafeArmProp $sh 'AllowNewSession'
                ActiveSessions    = SafeArmProp $sh 'Session'
                AssignedUser      = Protect-Username (SafeArmProp $sh 'AssignedUser')
                UpdateState       = SafeArmProp $sh 'UpdateState'
                LastHeartBeat     = SafeArmProp $sh 'LastHeartBeat'
            })

            # ── Resolve backing VM ──
            $vm = $null
            $vmStatus = $null

            # Tier 1: Host pool's RG cache
            if ($vmCacheByRg.ContainsKey($hpRg) -and $vmCacheByRg[$hpRg].ContainsKey($vmName)) {
                $vm = $vmCacheByRg[$hpRg][$vmName]
                $vmStatus = if ($vmStatusCacheByRg.ContainsKey($hpRg)) { $vmStatusCacheByRg[$hpRg][$vmName] } else { $null }
            }
            # Tier 2: Cross-RG index
            elseif ($vmCacheByName.ContainsKey($vmName)) {
                $vm = $vmCacheByName[$vmName]
            }
            # Tier 3: On-demand discovery
            else {
                try {
                    $vmResource = Invoke-WithRetry { Get-AzResource -ResourceType "Microsoft.Compute/virtualMachines" -Name $vmName -ErrorAction SilentlyContinue | Select-Object -First 1 }
                    if ($vmResource) {
                        $discoveredRg = $vmResource.ResourceGroupName
                        if (-not $vmCacheByRg.ContainsKey($discoveredRg)) {
                            $rgVmModels = @(Get-AzVM -ResourceGroupName $discoveredRg -ErrorAction SilentlyContinue)
                            $rgVmStatuses = @(Get-AzVM -ResourceGroupName $discoveredRg -Status -ErrorAction SilentlyContinue)
                            $vmCacheByRg[$discoveredRg] = @{}
                            $vmStatusCacheByRg[$discoveredRg] = @{}
                            foreach ($v in $rgVmModels) {
                                $vmCacheByRg[$discoveredRg][$v.Name] = $v
                                $vmCacheByName[$v.Name] = $v
                            }
                            foreach ($v in $rgVmStatuses) {
                                $vmStatusCacheByRg[$discoveredRg][$v.Name] = $v
                            }
                        }
                        $vm = $vmCacheByRg[$discoveredRg][$vmName]
                        $vmStatus = $vmStatusCacheByRg[$discoveredRg][$vmName]
                    }
                }
                catch { }
            }

            if (-not $vm) { continue }

            # Power state resolution
            $power = "Unknown"
            if ($vmStatus) {
                $statuses = $null
                if ($vmStatus.PSObject.Properties.Name -contains 'Statuses') {
                    $statuses = $vmStatus.Statuses
                }
                elseif ($vmStatus.PSObject.Properties.Name -contains 'InstanceView') {
                    $iv = $vmStatus.InstanceView
                    if ($null -ne $iv -and $iv.PSObject.Properties.Name -contains 'Statuses') {
                        $statuses = $iv.Statuses
                    }
                }
                if ($statuses) {
                    $powerCode = ($statuses | Where-Object { $_.Code -like 'PowerState/*' } | Select-Object -First 1)
                    if ($powerCode) { $power = ($powerCode.Code -split '/')[-1] }
                }
                if ($power -eq "Unknown" -and $vmStatus.PSObject.Properties.Name -contains 'PowerState') {
                    $ps = $vmStatus.PowerState
                    if ($ps) { $power = $ps -replace 'VM ', '' }
                }
            }

            # Image reference
            $imgRef = $vm.StorageProfile.ImageReference
            $imagePublisher = if ($imgRef) { SafeProp $imgRef 'Publisher' } else { $null }
            $imageOffer     = if ($imgRef) { SafeProp $imgRef 'Offer' } else { $null }
            $imageSku       = if ($imgRef) { SafeProp $imgRef 'Sku' } else { $null }
            $imageVersion   = if ($imgRef) { SafeProp $imgRef 'Version' } else { $null }
            $imageId        = if ($imgRef) { SafeProp $imgRef 'Id' } else { $null }
            $imageSource    = if ($imageId -and $imageId -match '/galleries/') { "ComputeGallery" }
                              elseif ($imageId -and $imageId -match '/images/') { "ManagedImage" }
                              elseif ($imagePublisher) { "Marketplace" }
                              else { "Custom" }

            # Security profile
            $secProfile   = $vm.SecurityProfile
            $securityType = if ($secProfile) { SafeProp $secProfile 'SecurityType' } else { $null }
            $uefiSettings = if ($secProfile) { SafeProp $secProfile 'UefiSettings' } else { $null }
            $secureBoot   = if ($uefiSettings) { SafeProp $uefiSettings 'SecureBootEnabled' } else { $null }
            $vtpm         = if ($uefiSettings) { SafeProp $uefiSettings 'VTpmEnabled' } else { $null }
            $hostEncryption = SafeProp $vm 'EncryptionAtHost'
            if ($null -eq $hostEncryption -and $secProfile) {
                $hostEncryption = SafeProp $secProfile 'EncryptionAtHost'
            }

            # OS disk
            $osDisk         = $vm.StorageProfile.OsDisk
            $osDiskType     = if ($osDisk -and $osDisk.ManagedDisk) { SafeProp $osDisk.ManagedDisk 'StorageAccountType' } else { "Unknown" }
            $osDiskEphemeral = if ($osDisk -and $osDisk.DiffDiskSettings) { $true } else { $false }

            # Disk encryption type
            $osDiskName = if ($osDisk) { SafeProp $osDisk 'Name' } else { $null }
            $osDiskEncryptionType = $null
            if ($osDiskName) {
                $vmRg = $vm.ResourceGroupName
                if (-not $vmRg) { $vmRg = $hpRg }
                $cacheKey = "$vmRg/$osDiskName"
                if ($script:diskEncCache.ContainsKey($cacheKey)) {
                    $osDiskEncryptionType = $script:diskEncCache[$cacheKey]
                }
                else {
                    try {
                        $diskObj = Get-AzDisk -ResourceGroupName $vmRg -DiskName $osDiskName -ErrorAction SilentlyContinue
                        if ($diskObj -and $diskObj.Encryption) {
                            $osDiskEncryptionType = SafeProp $diskObj.Encryption 'Type'
                        }
                        $script:diskEncCache[$cacheKey] = $osDiskEncryptionType
                    }
                    catch {
                        $script:diskEncCache[$cacheKey] = $null
                    }
                }
            }

            # NIC data
            $nicSubnetId   = $null
            $nicNsgId      = $null
            $nicPrivateIp  = $null
            $accelNetEnabled = $false
            $nicRefs = $vm.NetworkProfile.NetworkInterfaces
            if ($nicRefs -and @($nicRefs).Count -gt 0) {
                $nicId = $nicRefs[0].Id
                if ($nicId) {
                    $nicIdParts = $nicId -split '/'
                    $nicRg = if ($nicIdParts.Count -ge 5) { $nicIdParts[4] } else { $hpRg }
                    $nicName = $nicIdParts[-1]

                    if (-not $nicCacheByRg.ContainsKey($nicRg)) {
                        try {
                            $nics = @(Get-AzNetworkInterface -ResourceGroupName $nicRg -ErrorAction SilentlyContinue)
                            $nicCacheByRg[$nicRg] = @{}
                            foreach ($n in $nics) {
                                $nicCacheByRg[$nicRg][$n.Name] = $n
                            }
                        }
                        catch { $nicCacheByRg[$nicRg] = @{} }
                    }

                    $nic = $null
                    if ($nicCacheByRg[$nicRg].ContainsKey($nicName)) {
                        $nic = $nicCacheByRg[$nicRg][$nicName]
                    }

                    if ($nic) {
                        $ipConfig = $nic.IpConfigurations | Select-Object -First 1
                        if ($ipConfig) {
                            $nicSubnetId  = SafeProp $ipConfig.Subnet 'Id'
                            $nicPrivateIp = SafeProp $ipConfig 'PrivateIpAddress'
                        }
                        $nicNsgId = SafeProp $nic.NetworkSecurityGroup 'Id'
                        $accelNetEnabled = if ($nic.EnableAcceleratedNetworking) { $true } else { $false }
                    }
                }
            }

            # Identity type
            $identityType = if ($vm.Identity) { SafeProp $vm.Identity 'Type' } else { $null }

            # VM Extensions
            $extensions = SafeArray $vm.Extensions
            $extTypes = @($extensions | ForEach-Object {
                $t = SafeProp $_ 'VirtualMachineExtensionType'
                if (-not $t) { $t = SafeProp $_ 'Type' }
                if (-not $t) { $t = SafeProp $_ 'ExtensionType' }
                $t
            })

            $hasAadExtension      = @($extTypes | Where-Object { $_ -match 'AADLoginForWindows|AADIntuneLogin|AADJ' }).Count -gt 0
            $hasAmaAgent          = @($extTypes | Where-Object { $_ -match 'AzureMonitorWindowsAgent|AzureMonitorLinuxAgent|AMA' }).Count -gt 0
            $hasMmaAgent          = @($extTypes | Where-Object { $_ -match 'MicrosoftMonitoringAgent|OmsAgentForLinux|MMA' }).Count -gt 0
            $hasEndpointProtection = @($extTypes | Where-Object { $_ -match 'MDE|EndpointSecurity|IaaSAntimalware|Antimalware|WindowsDefender' }).Count -gt 0
            $hasGuestConfig       = @($extTypes | Where-Object { $_ -match 'ConfigurationforWindows|ConfigurationforLinux|GuestConfig' }).Count -gt 0
            $hasDiskEncryption    = @($extTypes | Where-Object { $_ -match 'AzureDiskEncryption' }).Count -gt 0

            # License type
            $vmLicenseType = SafeProp $vm 'LicenseType'

            $hpRgForVm = if ($vm.ResourceGroupName) { $vm.ResourceGroupName } else { $hpRg }

            # Zones
            $zones = if ($vm.Zones) { ($vm.Zones -join ",") } else { "" }

            # Keep raw ARM ID and VM name for metrics/log analytics collection (before PII scrubbing)
            $rawId = Get-ArmIdSafe $vm
            if ($rawId) { $rawVmIds.Add($rawId) }
            try { if ($vm.Name) { $rawVmNames.Add($vm.Name) } } catch { }

            $vms.Add([PSCustomObject]@{
                SubscriptionId       = Protect-SubscriptionId $subId
                ResourceGroup        = Protect-ResourceGroup $hpRgForVm
                HostPoolName         = Protect-HostPoolName $hpName
                SessionHostName      = Protect-VMName $vmName
                VMName               = Protect-VMName $vm.Name
                VMId                 = Protect-ArmId $rawId
                VMSize               = $vm.HardwareProfile.VmSize
                Region               = $vm.Location
                Zones                = $zones
                OSDiskType           = $osDiskType
                OSDiskEphemeral      = $osDiskEphemeral
                DataDiskCount        = (SafeCount $vm.StorageProfile.DataDisks)
                PowerState           = $power
                ImagePublisher       = $imagePublisher
                ImageOffer           = $imageOffer
                ImageSku             = $imageSku
                ImageVersion         = $imageVersion
                ImageId              = Protect-ArmId $imageId
                ImageSource          = $imageSource
                AccelNetEnabled      = $accelNetEnabled
                SubnetId             = Protect-SubnetId $nicSubnetId
                NsgId                = Protect-ArmId $nicNsgId
                PrivateIp            = Protect-IP $nicPrivateIp
                SecurityType         = $securityType
                SecureBoot           = $secureBoot
                VTpm                 = $vtpm
                HostEncryption       = $hostEncryption
                IdentityType         = $identityType
                HasAadExtension      = $hasAadExtension
                HasAmaAgent          = $hasAmaAgent
                HasMmaAgent          = $hasMmaAgent
                HasEndpointProtection = $hasEndpointProtection
                HasGuestConfig       = $hasGuestConfig
                HasDiskEncryption    = $hasDiskEncryption
                LicenseType          = $vmLicenseType
                OSDiskEncryptionType = $osDiskEncryptionType
                Tags                 = $(if ($ScrubPII) { $null } else { $vm.Tags })
                TimeCreated          = try { $vm.TimeCreated } catch { $null }
            })
        }
    }

    # ── Application Groups ──
    Write-Step -Step "App Groups" -Message "Enumerating..." -Status "Progress"
    try {
        $agObjs = Get-AzWvdApplicationGroup -ErrorAction SilentlyContinue
        foreach ($ag in SafeArray $agObjs) {
            $agName = SafeArmProp $ag 'Name'
            if (-not $agName) { $agName = $ag.Name }
            $agHpPath = SafeArmProp $ag 'HostPoolArmPath'
            $appGroups.Add([PSCustomObject]@{
                SubscriptionId = Protect-SubscriptionId $subId
                ResourceGroup  = Protect-ResourceGroup $(if ($ag.Id) { ($ag.Id -split '/')[4] } else { "" })
                AppGroupName   = Protect-Value -Value $agName -Prefix "AppGrp" -Length 4
                AppGroupType   = SafeArmProp $ag 'ApplicationGroupType'
                HostPoolArmPath = Protect-ArmId $agHpPath
                HostPoolName   = Protect-HostPoolName (Get-NameFromArmId $agHpPath)
                FriendlyName   = $(if ($ScrubPII) { '[SCRUBBED]' } else { SafeArmProp $ag 'FriendlyName' })
                Description    = $(if ($ScrubPII) { '[SCRUBBED]' } else { SafeArmProp $ag 'Description' })
            })
        }
    }
    catch {
        Write-Step -Step "App Groups" -Message "Failed — $($_.Exception.Message)" -Status "Warn"
    }

    # ── Scaling Plans ──
    Write-Step -Step "Scaling Plans" -Message "Enumerating..." -Status "Progress"
    try {
        $spObjs = Invoke-WithRetry { Get-AzResource -ResourceType "Microsoft.DesktopVirtualization/scalingPlans" -ExpandProperties -ErrorAction SilentlyContinue }
        foreach ($sp in SafeArray $spObjs) {
            Expand-ScalingPlanEvidence -PlanResource $sp -SubId $subId
        }
    }
    catch {
        Write-Step -Step "Scaling Plans" -Message "Failed — $($_.Exception.Message)" -Status "Warn"
    }

    # ── VM Scale Sets ──
    Write-Step -Step "VMSS" -Message "Enumerating..." -Status "Progress"
    try {
        $vmssResources = Get-AzVmss -ErrorAction SilentlyContinue
        foreach ($vmssObj in SafeArray $vmssResources) {
            $vmssName = $vmssObj.Name
            $vmssRg   = $vmssObj.ResourceGroupName
            $vmssId   = Get-ArmIdSafe $vmssObj

            $vmss.Add([PSCustomObject]@{
                SubscriptionId = Protect-SubscriptionId $subId
                ResourceGroup  = Protect-ResourceGroup $vmssRg
                VMSSName       = Protect-Value -Value $vmssName -Prefix "VMSS" -Length 4
                VMSSId         = Protect-ArmId $vmssId
                VMSize         = $vmssObj.Sku.Name
                Capacity       = $vmssObj.Sku.Capacity
                Location       = $vmssObj.Location
                Zones          = if ($vmssObj.Zones) { ($vmssObj.Zones -join ",") } else { "" }
            })

            # VMSS Instances
            try {
                $vmssInstObjs = @(Get-AzVmssVM -ResourceGroupName $vmssRg -VMScaleSetName $vmssName -ErrorAction SilentlyContinue)
                foreach ($inst in $vmssInstObjs) {
                    $instId = $inst.InstanceId
                    $instPower = "Unknown"
                    try {
                        $instView = Get-AzVmssVM -ResourceGroupName $vmssRg -VMScaleSetName $vmssName -InstanceId $instId -InstanceView -ErrorAction SilentlyContinue
                        if ($instView -and $instView.Statuses) {
                            $pc = $instView.Statuses | Where-Object { $_.Code -like 'PowerState/*' } | Select-Object -First 1
                            if ($pc) { $instPower = ($pc.Code -split '/')[-1] }
                        }
                    }
                    catch { }

                    $vmssInstances.Add([PSCustomObject]@{
                        SubscriptionId = Protect-SubscriptionId $subId
                        ResourceGroup  = Protect-ResourceGroup $vmssRg
                        VMSSName       = Protect-Value -Value $vmssName -Prefix "VMSS" -Length 4
                        InstanceId     = $instId
                        Name           = Protect-VMName $inst.Name
                        VMSize         = if ($inst.Sku) { $inst.Sku.Name } else { $vmssObj.Sku.Name }
                        PowerState     = $instPower
                        Location       = $inst.Location
                        Zones          = if ($inst.Zones) { ($inst.Zones -join ",") } else { "" }
                    })
                }
            }
            catch {
                Write-Step -Step "VMSS Instances" -Message "Failed for $vmssName — $($_.Exception.Message)" -Status "Warn"
            }
        }
    }
    catch {
        Write-Step -Step "VMSS" -Message "Failed — $($_.Exception.Message)" -Status "Warn"
    }

    # ── Capacity Reservation Groups (optional) ──
    if ($IncludeCapacityReservations) {
        Write-Step -Step "Capacity Reservations" -Message "Enumerating..." -Status "Progress"
        try {
            $crApiUrl = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Compute/capacityReservationGroups?api-version=2024-03-01&`$expand=virtualMachines/`$ref"
            $crResp = Invoke-AzRestMethod -Uri $crApiUrl -Method GET -ErrorAction Stop
            if ($crResp.StatusCode -eq 200) {
                $crData = $crResp.Content | ConvertFrom-Json
                foreach ($crg in SafeArray $crData.value) {
                    $crgId   = $crg.id
                    $crgName = $crg.name

                    # Fetch individual reservations
                    try {
                        $crDetailUrl = "https://management.azure.com${crgId}/capacityReservations?api-version=2024-03-01"
                        $crDetailResp = Invoke-AzRestMethod -Uri $crDetailUrl -Method GET -ErrorAction Stop
                        if ($crDetailResp.StatusCode -eq 200) {
                            $crDetails = ($crDetailResp.Content | ConvertFrom-Json).value
                            foreach ($cr in SafeArray $crDetails) {
                                $crProps = $cr.properties
                                $vmRefs = @()
                                if ($crProps.PSObject.Properties.Name -contains 'virtualMachinesAssociated') {
                                    $vmRefs = @($crProps.virtualMachinesAssociated | ForEach-Object { $_.id })
                                }
                                $capacityReservationGroups.Add([PSCustomObject]@{
                                    SubscriptionId     = Protect-SubscriptionId $subId
                                    GroupName          = Protect-Value -Value $crgName -Prefix "CRG" -Length 4
                                    GroupId            = Protect-ArmId $crgId
                                    ReservationName    = Protect-Value -Value $cr.name -Prefix "CRes" -Length 4
                                    Location           = $cr.location
                                    Zones              = if ($cr.zones) { ($cr.zones -join ",") } else { "" }
                                    SKU                = if ($cr.sku) { $cr.sku.name } else { "" }
                                    AllocatedCapacity  = SafeProp $crProps 'capacity'
                                    ProvisioningState  = SafeProp $crProps 'provisioningState'
                                    ProvisioningTime   = SafeProp $crProps 'provisioningTime'
                                    UtilizedVMs        = $vmRefs.Count
                                    VMReferences       = $(if ($ScrubPII) { '[SCRUBBED]' } else { ($vmRefs -join ";") })
                                })
                            }
                        }
                    }
                    catch {
                        Write-Step -Step "CRG Detail" -Message "Failed for $crgName" -Status "Warn"
                    }
                }
            }
        }
        catch {
            Write-Step -Step "Capacity Reservations" -Message "Failed — $($_.Exception.Message)" -Status "Warn"
        }
    }

    Write-Step -Step "Subscription $subsProcessed" -Message "Done — $(SafeCount $vms) VMs so far" -Status "Done"
}

Write-Host ""
Write-Host "  ARM collection complete: $(SafeCount $hostPools) host pools, $(SafeCount $vms) VMs, $(SafeCount $sessionHosts) session hosts" -ForegroundColor Green
Write-Host ""

# =========================================================
# STEP 2: Collect Azure Monitor Metrics
# =========================================================
if ($SkipAzureMonitorMetrics) {
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  Step 2: Azure Monitor Metrics — SKIPPED" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host ""
}
else {
    $totalSteps = if ($SkipLogAnalyticsQueries) { 3 } else { 4 }
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  Step 2 of $totalSteps`: Collecting Azure Monitor Metrics" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host ""

    # Normalize VM IDs: remove empty/whitespace entries and deduplicate
    $vmIds = @($rawVmIds | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ -ne '' } | Select-Object -Unique)
    $metricsEnd   = Get-Date
    $metricsStart = $metricsEnd.AddDays(-$MetricsLookbackDays)
    $grain = [TimeSpan]::FromMinutes($MetricsTimeGrainMinutes)

    Write-Host "  Collecting metrics for $(SafeCount $vmIds) VMs ($MetricsLookbackDays-day lookback, ${MetricsTimeGrainMinutes}m grain)" -ForegroundColor Gray
    Write-Host ""

    $metricsCollected = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $metricsProcessed = [ref]0
    $metricsTotal = SafeCount $vmIds

    $vmIds | ForEach-Object -Parallel {
        $vmId = $_
        $start = $using:metricsStart
        $end   = $using:metricsEnd
        $grain = $using:grain
        $bag   = $using:metricsCollected
        $processed = $using:metricsProcessed

        # Primary metrics: CPU + Memory
        $metricNames = @("Percentage CPU", "Available Memory Bytes")
        $aggregations = @("Average", "Maximum")

        $attempt = 0
        $maxAttempts = 4
        $success = $false

        while ($attempt -lt $maxAttempts -and -not $success) {
            $attempt++
            Write-Host "    Querying metrics for $vmId (attempt $attempt)" -ForegroundColor Gray
            try {
                # collect all aggregator results in one list
                $metricObjectsAll = [System.Collections.Generic.List[object]]::new()
                foreach ($aggType in $aggregations) {
                    $objs = Get-AzMetric `
                        -ResourceId $vmId `
                        -MetricName $metricNames `
                        -AggregationType $aggType `
                        -StartTime $start -EndTime $end -TimeGrain $grain `
                        -ErrorAction Stop
                    if ($objs) { $metricObjectsAll.AddRange($objs) }
                }

                if (-not $metricObjectsAll -or ($metricObjectsAll | Measure-Object).Count -eq 0) {
                    Write-Host "    Get-AzMetric returned no metric objects for $vmId" -ForegroundColor Yellow
                    try {
                        $res = Invoke-WithRetry { Get-AzResource -ResourceId $vmId -ErrorAction SilentlyContinue }
                        if ($res) { Write-Host "    Resource exists: $($res.ResourceType) $($res.Name) ($($res.Location))" -ForegroundColor Gray }
                        else { Write-Host "    Get-AzResource returned no resource for $vmId" -ForegroundColor Yellow }
                    } catch { Write-Host "    Failed to query resource metadata: ${($_.Exception.Message)}" -ForegroundColor Yellow }
                } else {
                    Write-Host "    Got metric types: $($metricObjectsAll.Count) for $vmId" -ForegroundColor Gray
                }

                foreach ($m in $metricObjectsAll) {
                    $mName = $m.Name.Value
                    foreach ($ts in $m.Timeseries) {
                        foreach ($pt in $ts.Data) {
                            if ($null -ne $pt.Average) {
                                $bag.Add([PSCustomObject]@{
                                    VmId        = $vmId
                                    Metric      = $mName
                                    Aggregation = 'Average'
                                    TimeStamp   = $pt.TimeStamp
                                    Value       = $pt.Average
                                })
                            }
                            if ($null -ne $pt.Maximum) {
                                $bag.Add([PSCustomObject]@{
                                    VmId        = $vmId
                                    Metric      = $mName
                                    Aggregation = 'Maximum'
                                    TimeStamp   = $pt.TimeStamp
                                    Value       = $pt.Maximum
                                })
                            }
                        }
                    }
                }
                $success = $true
            }
            catch {
                $msg = $_.Exception.Message
                Write-Host "    Get-AzMetric error for ${vmId}: ${msg}" -ForegroundColor Yellow
                if ($msg -match '429|throttl' -and $attempt -lt $maxAttempts) {
                    $backoff = @(15, 45, 135)[$attempt - 1]
                    Write-Host "    throttled, backing off ${backoff} seconds" -ForegroundColor Yellow
                    Start-Sleep -Seconds $backoff
                }
                # Non-throttle errors or final attempt: will retry until attempts exhausted
            }
        }

        # Secondary metrics: Disk (best-effort, no retry)
        try {
            $diskMetricNames = @("OS Disk IOPS Consumed Percentage", "OS Disk Queue Depth", "Data Disk IOPS Consumed Percentage")
            $diskMetrics = Get-AzMetric `
                -ResourceId $vmId `
                -MetricName $diskMetricNames `
                -Aggregation @("Average", "Maximum") `
                -StartTime $start -EndTime $end -TimeGrain $grain `
                -ErrorAction SilentlyContinue

            foreach ($m in @($diskMetrics)) {
                $mName = $m.Name.Value
                foreach ($ts in $m.Timeseries) {
                    foreach ($pt in $ts.Data) {
                        foreach ($agg in @("Average", "Maximum")) {
                            $value = $null
                            if ($agg -eq "Average" -and $null -ne $pt.Average) { $value = $pt.Average }
                            if ($agg -eq "Maximum" -and $null -ne $pt.Maximum) { $value = $pt.Maximum }
                            if ($null -ne $value) {
                                $bag.Add([PSCustomObject]@{
                                    VmId        = $vmId
                                    Metric      = $mName
                                    Aggregation = $agg
                                    TimeStamp   = $pt.TimeStamp
                                    Value       = $value
                                })
                            }
                        }
                    }
                }
            }
        }
        catch { }

        [System.Threading.Interlocked]::Increment($processed) | Out-Null
        # update progress bar in parallel runspaces
        try {
            $pct = [math]::Round(($processed.Value / $using:metricsTotal) * 100)
            Write-Progress -Activity "Collecting Azure Monitor metrics" -Status "$($processed.Value)/$($using:metricsTotal) VMs" -PercentComplete $pct
        } catch { }

    } -ThrottleLimit 15

    # Move from ConcurrentBag to List (and scrub VmId if needed)
    foreach ($item in $metricsCollected) {
        if ($ScrubPII) { $item.VmId = Protect-ArmId $item.VmId }
        $vmMetrics.Add($item)
    }

    Write-Host "  ✓ Metrics collected: $(SafeCount $vmMetrics) datapoints for $metricsTotal VMs" -ForegroundColor Green
    Write-Host ""

    # ── Incident Window Metrics (optional) ──
    if ($IncludeIncidentWindow) {
        Write-Host "  Collecting incident window metrics ($IncidentWindowStart → $IncidentWindowEnd)..." -ForegroundColor Cyan

        $incidentCollected = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

        $vmIds | ForEach-Object -Parallel {
            $vmId = $_
            $start = $using:IncidentWindowStart
            $end   = $using:IncidentWindowEnd
            $grain = $using:grain
            $bag   = $using:incidentCollected

            try {
                $metricObjects = Get-AzMetric `
                    -ResourceId $vmId `
                    -MetricName @("Percentage CPU", "Available Memory Bytes") `
                    -Aggregation @("Average", "Maximum") `
                    -StartTime $start -EndTime $end -TimeGrain $grain `
                    -ErrorAction Stop

                foreach ($m in $metricObjects) {
                    $mName = $m.Name.Value
                    foreach ($ts in $m.Timeseries) {
                        foreach ($pt in $ts.Data) {
                            foreach ($agg in @("Average", "Maximum")) {
                                $value = $null
                                if ($agg -eq "Average" -and $null -ne $pt.Average) { $value = $pt.Average }
                                if ($agg -eq "Maximum" -and $null -ne $pt.Maximum) { $value = $pt.Maximum }
                                if ($null -ne $value) {
                                    $bag.Add([PSCustomObject]@{
                                        VmId        = $vmId
                                        Metric      = $mName
                                        Aggregation = $agg
                                        TimeStamp   = $pt.TimeStamp
                                        Value       = $value
                                    })
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        } -ThrottleLimit $MetricsParallel

        foreach ($item in $incidentCollected) {
            if ($ScrubPII) { $item.VmId = Protect-ArmId $item.VmId }
            $vmMetricsIncident.Add($item)
        }

        Write-Host "  ✓ Incident metrics: $(SafeCount $vmMetricsIncident) datapoints" -ForegroundColor Green
        Write-Host ""
    }
}

# =========================================================
# STEP 3: Log Analytics (KQL) Queries
# =========================================================
if ($SkipLogAnalyticsQueries -or (SafeCount $LogAnalyticsWorkspaceResourceIds) -eq 0) {
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    if ($SkipLogAnalyticsQueries) {
        Write-Host "  Step 3: Log Analytics Queries — SKIPPED (-SkipLogAnalyticsQueries)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  Step 3: Log Analytics Queries — SKIPPED (no workspace IDs provided)" -ForegroundColor Yellow
    }
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host ""
}
else {
    $totalSteps = if ($SkipAzureMonitorMetrics) { 3 } else { 4 }
    $stepNum = if ($SkipAzureMonitorMetrics) { 2 } else { 3 }
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  Step $stepNum of $totalSteps`: Log Analytics Queries" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host ""

    $queryStart = (Get-Date).AddDays(-$MetricsLookbackDays)
    $queryEnd   = Get-Date


    # Build query dispatch list
    $queryDispatchList = @(
        @{ Label = "CurrentWindow_TableDiscovery";          Query = $kqlQueries["kqlTableDiscovery"] },
        @{ Label = "CurrentWindow_WVDConnections";          Query = $kqlQueries["kqlWvdConnections"] },
        @{ Label = "CurrentWindow_WVDShortpathUsage";       Query = $kqlQueries["kqlShortpathUsage"] },
        @{ Label = "CurrentWindow_WVDPeakConcurrency";      Query = $kqlQueries["kqlPeakConcurrency"] },
        @{ Label = "CurrentWindow_WVDAutoscaleActivity";    Query = $kqlQueries["kqlAutoscaleActivity"] },
        @{ Label = "CurrentWindow_WVDAutoscaleDetailed";    Query = $kqlQueries["kqlAutoscaleDetailedActivity"] },
        @{ Label = "CurrentWindow_SessionDuration";         Query = $kqlQueries["kqlSessionDuration"] },
        @{ Label = "CurrentWindow_ProfileLoadPerformance";  Query = $kqlQueries["kqlProfileLoadPerformance"] },
        @{ Label = "CurrentWindow_ConnectionQuality";       Query = $kqlQueries["kqlConnectionQuality"] },
        @{ Label = "CurrentWindow_ConnectionQualityByRegion"; Query = $kqlQueries["kqlConnectionQualityByRegion"] },
        @{ Label = "CurrentWindow_ConnectionErrors";        Query = $kqlQueries["kqlConnectionErrors"] },
        @{ Label = "CurrentWindow_Disconnects";             Query = $kqlQueries["kqlDisconnects"] },
        @{ Label = "CurrentWindow_DisconnectReasons";       Query = $kqlQueries["kqlDisconnectReasons"] },
        @{ Label = "CurrentWindow_DisconnectsByHost";       Query = $kqlQueries["kqlDisconnectsByHost"] },
        @{ Label = "CurrentWindow_HourlyConcurrency";       Query = $kqlQueries["kqlHourlyConcurrency"] },
        @{ Label = "CurrentWindow_CrossRegionConnections";  Query = $kqlQueries["kqlCrossRegionConnections"] },
        @{ Label = "CurrentWindow_LoginTime";               Query = $kqlQueries["kqlLoginTime"] },
        @{ Label = "CurrentWindow_ConnectionSuccessRate";   Query = $kqlQueries["kqlConnectionSuccessRate"] },
        @{ Label = "CurrentWindow_ProcessCpu";              Query = $kqlQueries["kqlProcessCpu"] },
        @{ Label = "CurrentWindow_ProcessCpuSummary";       Query = $kqlQueries["kqlProcessCpuSummary"] },
        @{ Label = "CurrentWindow_ProcessMemory";           Query = $kqlQueries["kqlProcessMemory"] },
        @{ Label = "CurrentWindow_CpuPercentiles";          Query = $kqlQueries["kqlCpuPercentiles"] },
        @{ Label = "CurrentWindow_ReconnectionLoops";       Query = $kqlQueries["kqlReconnectionLoops"] },
        @{ Label = "CurrentWindow_DisconnectCpuCorrelation"; Query = $kqlQueries["kqlDisconnectCpuCorrelation"] },
        @{ Label = "CurrentWindow_ShortpathEffectiveness";  Query = $kqlQueries["kqlShortpathEffectiveness"] },
        @{ Label = "CurrentWindow_ShortpathByClient";       Query = $kqlQueries["kqlShortpathByClient"] },
        @{ Label = "CurrentWindow_ShortpathTransportRTT";   Query = $kqlQueries["kqlShortpathTransportRTT"] },
        @{ Label = "CurrentWindow_ShortpathByGateway";      Query = $kqlQueries["kqlShortpathByGateway"] },
        @{ Label = "CurrentWindow_MultiLinkTransport";      Query = $kqlQueries["kqlMultiLinkTransport"] },
        @{ Label = "CurrentWindow_AgentHealthStatus";       Query = $kqlQueries["kqlAgentHealthStatus"] },
        @{ Label = "CurrentWindow_AgentVersionDistribution"; Query = $kqlQueries["kqlAgentVersionDistribution"] },
        @{ Label = "CurrentWindow_AgentHealthChecks";       Query = $kqlQueries["kqlAgentHealthChecks"] },
        @{ Label = "CurrentWindow_ConnectionEnvironment";   Query = $kqlQueries["kqlConnectionEnvironment"] },
        @{ Label = "CurrentWindow_ErrorClassification";     Query = $kqlQueries["kqlErrorClassification"] },
        @{ Label = "CurrentWindow_CheckpointLoginDecomp";   Query = $kqlQueries["kqlCheckpointLoginDecomposition"] },
        @{ Label = "CurrentWindow_DisconnectHeatmap";       Query = $kqlQueries["kqlDisconnectHeatmap"] }
    ) | Where-Object { $null -ne $_.Query }

    # progress tracking for queries
    $script:laProcessed = 0
    $remainingQueryCount = ($queryDispatchList | Where-Object { $_.Label -ne "CurrentWindow_TableDiscovery" }).Count
    $laTotal = (SafeCount $LogAnalyticsWorkspaceResourceIds) * $remainingQueryCount

    Write-Host "  Dispatching $(SafeCount $queryDispatchList) queries across $(SafeCount $LogAnalyticsWorkspaceResourceIds) workspace(s)" -ForegroundColor Gray
    Write-Host ""

    foreach ($wsId in $LogAnalyticsWorkspaceResourceIds) {
        # Handle cross-subscription workspace access
        $wsSubId = Get-SubFromArmId $wsId
        if ($wsSubId -and $wsSubId -ne $script:currentSubContext) {
            Write-Host "    switching context to workspace subscription $wsSubId" -ForegroundColor Gray
            try {
                Invoke-WithRetry { Set-AzContext -SubscriptionId $wsSubId -TenantId $TenantId -ErrorAction Stop | Out-Null }
                $script:currentSubContext = $wsSubId
            }
            catch {
                Write-Step -Step "KQL" -Message "Cannot access workspace subscription $wsSubId — $($_.Exception.Message)" -Status "Error"
                continue
            }
        }

        $wsName = Get-NameFromArmId $wsId
        Write-Step -Step "KQL" -Message "Workspace: $wsName" -Status "Progress"

        # Run TableDiscovery first (sequential) to validate connectivity
        $tdQuery = $queryDispatchList | Where-Object { $_.Label -eq "CurrentWindow_TableDiscovery" } | Select-Object -First 1
        if ($tdQuery) {
            $tdResult = Invoke-LaQuery -WorkspaceResourceId $wsId -Label $tdQuery.Label -Query $tdQuery.Query -StartTime $queryStart -EndTime $queryEnd
            foreach ($r in SafeArray $tdResult) {
                if ($ScrubPII) {
                    $r.WorkspaceResourceId = Protect-ArmId $r.WorkspaceResourceId
                    Protect-KqlRow $r
                }
                $laResults.Add($r)
            }

            $tdStatus = ($tdResult | Where-Object { $_.PSObject.Properties.Name -contains 'Status' } | Select-Object -First 1)
            if ($tdStatus -and $tdStatus.Status -in @("WorkspaceNotFound", "QueryFailed", "InvalidWorkspaceId")) {
                Write-Step -Step "KQL" -Message "Workspace unreachable ($($tdStatus.Status)) — skipping remaining queries" -Status "Error"
                if ($tdStatus.Status -eq "WorkspaceNotFound") {
                    Write-Host "    Verify the workspace resource ID is correct and that you have Log Analytics Reader access." -ForegroundColor Yellow
                    Write-Host "    Expected format: /subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>" -ForegroundColor Gray
                }
                continue
            }
        }

        # Run remaining queries in parallel
        $remainingQueries = $queryDispatchList | Where-Object { $_.Label -ne "CurrentWindow_TableDiscovery" }
        $kqlCollected = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

        # Serialize helper functions for parallel runspaces
        $invokeBody = (Get-Item "Function:\Invoke-LaQuery").ScriptBlock.ToString()
        $safePropBody = (Get-Item "Function:\SafeProp").ScriptBlock.ToString()
        $safeArrayBody = (Get-Item "Function:\SafeArray").ScriptBlock.ToString()

        $remainingQueries | ForEach-Object -Parallel {
            $kq    = $_
            $wsId  = $using:wsId
            $start = $using:queryStart
            $end   = $using:queryEnd
            $bag   = $using:kqlCollected

            # Re-create helper functions in parallel runspace
            Set-Item "Function:\Invoke-LaQuery" -Value ([scriptblock]::Create($using:invokeBody))
            Set-Item "Function:\SafeProp"       -Value ([scriptblock]::Create($using:safePropBody))
            Set-Item "Function:\SafeArray"      -Value ([scriptblock]::Create($using:safeArrayBody))

            try {
                $results = Invoke-LaQuery -WorkspaceResourceId $wsId -Label $kq.Label -Query $kq.Query -StartTime $start -EndTime $end
                foreach ($r in @($results)) {
                    $bag.Add($r)
                }
            }
            catch {
                $bag.Add([PSCustomObject]@{
                    WorkspaceResourceId = $wsId
                    Label               = $kq.Label
                    QueryName           = "Meta"
                    Status              = "QueryFailed"
                    Error               = $_.Exception.Message
                    RowCount            = 0
                })
            }
        } -ThrottleLimit $KqlParallel

        # increment workspace-based counter and update progress bar
        $script:laProcessed += $remainingQueries.Count
        try {
            $pct2 = [math]::Round(($script:laProcessed / $laTotal) * 100)
            Write-Progress -Activity "Running KQL queries" -Status "$script:laProcessed/$laTotal queries" -PercentComplete $pct2
        } catch { }

        foreach ($item in $kqlCollected) {
            if ($ScrubPII) {
                $item.WorkspaceResourceId = Protect-ArmId $item.WorkspaceResourceId
                Protect-KqlRow $item
            }
            $laResults.Add($item)
        }

        Write-Step -Step "KQL" -Message "$wsName — $(SafeCount $kqlCollected) results collected" -Status "Done"
    }

    Write-Host ""
    Write-Host "  ✓ KQL collection complete: $(SafeCount $laResults) total results" -ForegroundColor Green
    Write-Host ""
}

# =========================================================
# STEP 4 (optional): Quota Usage
# =========================================================
if ($IncludeQuotaUsage) {
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  Collecting Quota Usage" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host ""

    $avdRegions = @($vms | Where-Object { $_.Region } | Select-Object -ExpandProperty Region -Unique)

    foreach ($region in $avdRegions) {
        Write-Step -Step "Quota" -Message "Region: $region" -Status "Progress"
        try {
            # Switch to first subscription for quota query
            if ($script:currentSubContext -ne $SubscriptionIds[0]) {
                Invoke-WithRetry { Set-AzContext -SubscriptionId $SubscriptionIds[0] -TenantId $TenantId -ErrorAction Stop | Out-Null }
                $script:currentSubContext = $SubscriptionIds[0]
            }
            $usageData = @(Get-AzVMUsage -Location $region -ErrorAction Stop)

            foreach ($usage in $usageData) {
                $usageName  = SafeProp $usage.Name 'Value'
                $usageLocal = SafeProp $usage.Name 'LocalizedValue'
                $currentVal = $usage.CurrentValue
                $limitVal   = $usage.Limit

                # Only include relevant quota families
                if ($usageLocal -match 'Total Regional|Standard D|Standard E|Standard F|Standard B|Standard N|Standard L|Standard M|Standard H|DSv|ESv|FSv|BSv|NV|NC|ND') {
                    $available = $limitVal - $currentVal
                    $usagePct  = if ($limitVal -gt 0) { [math]::Round(($currentVal / $limitVal) * 100, 1) } else { 0 }

                    $quotaUsage.Add([PSCustomObject]@{
                        Region       = $region
                        Family       = $usageLocal
                        FamilyCode   = $usageName
                        CurrentUsage = $currentVal
                        Limit        = $limitVal
                        Available    = $available
                        UsagePct     = $usagePct
                    })
                }
            }
        }
        catch {
            Write-Step -Step "Quota" -Message "Failed for $region — $($_.Exception.Message)" -Status "Warn"
        }
    }

    Write-Host "  ✓ Quota data: $(SafeCount $quotaUsage) entries across $(SafeCount $avdRegions) regions" -ForegroundColor Green
    Write-Host ""
}

# =========================================================
# EXPORT: Write Collection Pack
# =========================================================
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Exporting Collection Pack" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

function Export-PackJson {
    param([string]$FileName, [object]$Data)
    $filePath = Join-Path $outFolder $FileName
    $Data | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $filePath -Encoding UTF8
    $count = if ($Data -is [System.Collections.ICollection]) { $Data.Count } else { @($Data).Count }
    Write-Host "    ✓ $FileName — $count items" -ForegroundColor Green
}

# Core data files
Export-PackJson -FileName "host-pools.json" -Data $hostPools
Export-PackJson -FileName "session-hosts.json" -Data $sessionHosts
Export-PackJson -FileName "virtual-machines.json" -Data $vms
Export-PackJson -FileName "vmss.json" -Data $vmss
Export-PackJson -FileName "vmss-instances.json" -Data $vmssInstances
Export-PackJson -FileName "app-groups.json" -Data $appGroups
Export-PackJson -FileName "scaling-plans.json" -Data $scalingPlans
Export-PackJson -FileName "scaling-plan-assignments.json" -Data $scalingPlanAssignments
Export-PackJson -FileName "scaling-plan-schedules.json" -Data $scalingPlanSchedules
Export-PackJson -FileName "metrics-baseline.json" -Data $vmMetrics
Export-PackJson -FileName "metrics-incident.json" -Data $vmMetricsIncident
Export-PackJson -FileName "la-results.json" -Data $laResults
Export-PackJson -FileName "capacity-reservation-groups.json" -Data $capacityReservationGroups
Export-PackJson -FileName "quota-usage.json" -Data $quotaUsage

# Metadata
$metadata = [PSCustomObject]@{
    SchemaVersion            = $script:SchemaVersion
    ScriptVersion            = $script:ScriptVersion
    CollectionTimestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
    SubscriptionIds          = @($SubscriptionIds | ForEach-Object { Protect-SubscriptionId $_ })
    TenantId                 = $(if ($ScrubPII) { '****-****-****' } else { $TenantId })
    MetricsLookbackDays      = $MetricsLookbackDays
    IncidentWindowQueried    = [bool]$IncludeIncidentWindow
    SkipAzureMonitorMetrics  = [bool]$SkipAzureMonitorMetrics
    SkipLogAnalyticsQueries  = [bool]$SkipLogAnalyticsQueries
    SkipActualCosts          = $true  # This collector doesn't collect cost data
    PIIScrubbed              = [bool]$ScrubPII
    Counts                   = [PSCustomObject]@{
        HostPools    = SafeCount $hostPools
        SessionHosts = SafeCount $sessionHosts
        VMs          = SafeCount $vms
        VMSS         = SafeCount $vmss
        Metrics      = SafeCount $vmMetrics
        KQLResults   = SafeCount $laResults
        AppGroups    = SafeCount $appGroups
        ScalingPlans = SafeCount $scalingPlans
    }
    AnalysisErrors           = @()
    CollectorTool            = "avd-data-collector"
    CollectorVersion         = $script:ScriptVersion
}

$metadata | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $outFolder "collection-metadata.json") -Encoding UTF8
Write-Host "    ✓ collection-metadata.json" -ForegroundColor Green

# ── Create ZIP ──
# make sure diagnostic transcript is closed before archiving
if (Get-Command Stop-Transcript -ErrorAction SilentlyContinue) { try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { } }
$zipPath = "$outFolder.zip"
try {
    Compress-Archive -Path $outFolder -DestinationPath $zipPath -Force
    Write-Host ""
    Write-Host "  ✓ Collection pack created: $zipPath" -ForegroundColor Green

    # Calculate size
    $zipSize = (Get-Item $zipPath).Length
    $sizeMB = [math]::Round($zipSize / 1MB, 2)
    Write-Host "    Size: $sizeMB MB" -ForegroundColor Gray
}
catch {
    Write-Host ""
    Write-Host "  ⚠ Could not create ZIP — data is in folder: $outFolder" -ForegroundColor Yellow
}

# make sure diagnostic transcript is closed
if (Get-Command Stop-Transcript -ErrorAction SilentlyContinue) {
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
}

# =========================================================
# Summary
# =========================================================
$elapsed = (Get-Date) - $script:collectionStart

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                     COLLECTION COMPLETE                               ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Host Pools:      $(SafeCount $hostPools)" -ForegroundColor White
Write-Host "  Session Hosts:   $(SafeCount $sessionHosts)" -ForegroundColor White
Write-Host "  VMs:             $(SafeCount $vms)" -ForegroundColor White
Write-Host "  Metrics:         $(SafeCount $vmMetrics) datapoints" -ForegroundColor White
Write-Host "  KQL Results:     $(SafeCount $laResults)" -ForegroundColor White
Write-Host "  Scaling Plans:   $(SafeCount $scalingPlans)" -ForegroundColor White
Write-Host "  App Groups:      $(SafeCount $appGroups)" -ForegroundColor White
if ($IncludeCapacityReservations) {
    Write-Host "  Capacity Res.:   $(SafeCount $capacityReservationGroups)" -ForegroundColor White
}
if ($ScrubPII) {
    Write-Host "  PII:     Scrubbed (identifiers anonymized)" -ForegroundColor Magenta
}
if ($IncludeQuotaUsage) {
    Write-Host "  Quota Entries:   $(SafeCount $quotaUsage)" -ForegroundColor White
}
Write-Host ""
Write-Host "  Runtime: $([math]::Round($elapsed.TotalMinutes, 1)) minutes" -ForegroundColor Gray
Write-Host "  Output:  $zipPath" -ForegroundColor Gray
Write-Host ""

if ((SafeCount $subsSkipped) -gt 0) {
    Write-Host "  ⚠ Skipped subscriptions: $($subsSkipped -join ', ')" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "  To analyze this data with the Enhanced AVD Evidence Pack:" -ForegroundColor Cyan
Write-Host "    .\Get-Enhanced-AVD-EvidencePack.ps1 -CollectionPack `"$zipPath`"" -ForegroundColor White
Write-Host ""
