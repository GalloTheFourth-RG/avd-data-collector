<#
.SYNOPSIS
    Downloads the AVD Data Collector from GitHub into the current directory.
.DESCRIPTION
    One-liner installer — downloads Collect-AVDData.ps1 and all 36 KQL query files.
    Run this in an empty folder, then use Collect-AVDData.ps1 as normal.

    Usage:
        irm "https://raw.githubusercontent.com/GalloTheFourth-RG/avd-data-collector/main/Install-AVDCollector.ps1" | iex
#>

$ErrorActionPreference = "Stop"
$repo = "https://raw.githubusercontent.com/GalloTheFourth-RG/avd-data-collector/main"

Write-Host ""
Write-Host "  AVD Data Collector — Installer" -ForegroundColor Cyan
Write-Host "  ==============================" -ForegroundColor Cyan
Write-Host ""

# Download main script
Write-Host "  Downloading Collect-AVDData.ps1..." -ForegroundColor Gray
Invoke-RestMethod "$repo/Collect-AVDData.ps1" -OutFile "Collect-AVDData.ps1"

# Create queries folder
$null = New-Item -ItemType Directory -Path "queries" -Force

# KQL query files
$queries = @(
    "kqlAgentHealthChecks"
    "kqlAgentHealthStatus"
    "kqlAgentVersionDistribution"
    "kqlAutoscaleActivity"
    "kqlAutoscaleDetailedActivity"
    "kqlCheckpointLoginDecomposition"
    "kqlConnectionEnvironment"
    "kqlConnectionErrors"
    "kqlConnectionQuality"
    "kqlConnectionQualityByRegion"
    "kqlConnectionSuccessRate"
    "kqlCpuPercentiles"
    "kqlCrossRegionConnections"
    "kqlDisconnectCpuCorrelation"
    "kqlDisconnectHeatmap"
    "kqlDisconnectReasons"
    "kqlDisconnects"
    "kqlDisconnectsByHost"
    "kqlErrorClassification"
    "kqlHourlyConcurrency"
    "kqlLoginTime"
    "kqlMultiLinkTransport"
    "kqlPeakConcurrency"
    "kqlProcessCpu"
    "kqlProcessCpuSummary"
    "kqlProcessMemory"
    "kqlProfileLoadPerformance"
    "kqlReconnectionLoops"
    "kqlSessionDuration"
    "kqlShortpathByClient"
    "kqlShortpathByGateway"
    "kqlShortpathEffectiveness"
    "kqlShortpathTransportRTT"
    "kqlShortpathUsage"
    "kqlTableDiscovery"
    "kqlWvdConnections"
)

Write-Host "  Downloading $($queries.Count) KQL queries..." -ForegroundColor Gray
$downloaded = 0
foreach ($q in $queries) {
    Invoke-RestMethod "$repo/queries/$q.kql" -OutFile "queries/$q.kql"
    $downloaded++
}

Write-Host ""
Write-Host "  Done! Downloaded Collect-AVDData.ps1 + $downloaded query files." -ForegroundColor Green
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Cyan
Write-Host "    .\Collect-AVDData.ps1 -TenantId `"your-tenant`" -SubscriptionIds @(`"sub-id`") -DryRun" -ForegroundColor White
Write-Host ""
