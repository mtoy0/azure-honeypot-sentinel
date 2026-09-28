# Azure Honeypot + Microsoft Sentinel SIEM

## Overview
Deployed an intentionally exposed Windows VM in Azure to attract real-world brute-force attacks, forwarded security logs to Microsoft Sentinel via Azure Monitor Agent, enriched attacker IPs with GeoIP data, and built detections, incidents, and an attack map. Then hardened the environment and measured the impact.

## Architecture
<!-- Add diagram: screenshots/architecture.png -->
Internet → NSG (open) → Windows VM (honeypot) → Azure Monitor Agent → Data Collection Rule → Log Analytics Workspace → Microsoft Sentinel (analytics rules, workbook, incidents)

## Tools & Technologies
- Microsoft Azure (VM, NSG, Log Analytics, Azure Monitor Agent, DCR)
- Microsoft Sentinel (SIEM)
- KQL (Kusto Query Language)
- GeoIP watchlist enrichment
- NIST SP 800-61 incident response

## Results
| Metric | Value |
|---|---|
| Observation period | X days |
| Total failed logins (EventID 4625) | X |
| Unique attacking IPs | X |
| Countries of origin | X |
| Time to first attack | X |
| Peak attacks/hour | X |
| Incidents generated | X |
| Attack reduction after hardening | X% |
| Total cost | $X |

### Top attempted usernames
1.
2.
3.

## Attack Map
<!-- screenshots/attack-map.png -->

## Detections
See [`kql/`](kql/) for all queries.

## Incident Response
See [`incidents/`](incidents/) for NIST 800-61 writeups.

## Hardening: Before vs After
| Control | Before | After |
|---|---|---|
| NSG inbound | Any/Any | My IP only |
| Windows Firewall | Off | On |
| Failed logins / 24h | X | X |

## Lessons Learned
-

## Teardown
Resource group deleted after project completion to avoid ongoing costs.
