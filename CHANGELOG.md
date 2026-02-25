# Changelog

All notable changes to the AVD Data Collector will be documented in this file.

## [1.0.0] — 2025-06-01

### Added
- Initial release
- ARM resource collection: host pools, session hosts, VMs, VMSS, app groups, scaling plans
- Azure Monitor metrics collection with parallel execution and retry logic
- 36 KQL queries covering connections, errors, disconnects, Shortpath, agent health, performance, profiles, and autoscale
- Capacity reservation group collection via ARM REST API
- Per-region vCPU quota collection
- Incident window metrics collection
- Dry run mode for collection preview
- Collection pack export (ZIP) compatible with Enhanced AVD Evidence Pack v4.12.0+
- Schema version 1.1 support
- Bulk VM pre-fetch optimization (per-RG instead of per-VM API calls)
- Cross-subscription Log Analytics workspace support
- Exponential backoff retry for API throttling (429)
