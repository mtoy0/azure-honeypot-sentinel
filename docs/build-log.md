# Build Log

## 2026-09-27 — Phase 0: Repo & account setup
**Did:**
- Created the GitHub repo `azure-honeypot-sentinel` with a template structure (README, docs/, kql/, incidents/, screenshots/) and pushed it from Git Bash
- Created a new Azure free account (Azure subscription 1), with $200 trial credit expiring Oct 27, 2026

**Settings / config:**
- Created resource group `rg-honeypot` (South Central US)
- Set a $40 monthly budget alert

**Problems & fixes:**
- None

**Running cost:** $0

---

## 2026-09-28 — Phase 1: Exposed VM + log pipeline
**Did:**
- Deployed `vm-honeypot`: Windows Server 2022 Datacenter, D2als_v6, Standard SSD, South Central US
- Opened it to the internet on purpose: NSG rule `DANGER_AllowAnyInbound` (priority 100, Any/Any/Allow), and Windows Defender Firewall turned off inside the VM
- Confirmed it was reachable by pinging the public IP from my laptop
- Created the Log Analytics workspace `law-honeypot` and enabled Microsoft Sentinel
- Installed the Windows Security Events solution and created the Data Collection Rule `dcr-honeypot` (All Security Events → `SecurityEvent` table)
- Confirmed `AzureMonitorWindowsAgent` was installed on the VM

**Problems & fixes:**
- B-series VM sizes failed with `NotAvailableForSubscription` on the trial. Switched to D2als_v6
- The Sentinel Content hub had moved to the Defender portal (security.microsoft.com). Installed the solution there
- Ran into a duplicate DCR during setup. Kept `dcr-honeypot` as the active rule
- The Domain firewall profile was still on (Private and Public were off)

**Screenshots taken:**
- `01-nsg-danger-allow-any-inbound.png`, `02-vm-windows-firewall-off.png`, `03-ping-honeypot-exposed.png`

**Running cost:** ~$0

---

## 2026-09-29 — Phase 2: Detection, enrichment, dashboard
**Did:**
- Confirmed security events were arriving in `law-honeypot`
- Ran the failed-logon (4625) query. Real brute-force traffic was already coming in
- Ran the summary metrics: 5,640 failed logons, 10 IPs, 96 usernames in 24h
- Checked successful external logons (4624): none
- Added GeoIP enrichment with the built-in `geo_info_from_ip_address()` (no watchlist needed): 7 countries, and `49.249.85.2` (Hyderabad) was about 95% of the traffic
- Pushed all KQL queries to `kql/` and removed the template placeholder query
- Built the **Honeypot Attack Dashboard** workbook: summary tiles, attack-origin map, failed logons per hour, top attacker IPs

**Screenshots taken:**
- `04-failed-logons-by-username.png`, `05-no-successful-external-logons.png`, `06-summary-metrics.png`, `07-geoip-failed-logons.png`, `08-attack-dashboard-map.png`, `09-azure-cost-day1.png`

**Running cost:** $1.05 (from trial credit; $198.95 left)

---

## 2026-10-04 — Phase 3: Follow-up review
**Did:**
- Re-ran the successful-logon (4624) query over 7 days. Found 3 `ANONYMOUS LOGON` NTLM network logons (Oct 1–2) from 44.251.136.206 and 142.93.143.8
- Determined they were unauthenticated null sessions from scanners, not a compromise. Documented this in the incident write-up and added a tuned query that excludes them

**Screenshots taken:**
- `10-anonymous-ntlm-logons.png`

---

## 2026-10-27 — End of data collection
- The Azure free-trial credit expired and the subscription stopped, so the honeypot stopped collecting data
- Log data later aged out of the workspace under default retention. The workbook still exists but is empty (checked Nov 9, 2026)

---

## 2026-11-09 — Phase 4: Documentation
- Added screenshots (with the account email cropped out), filled in the README with day-1 results, and wrote the NIST 800-61 incident report
