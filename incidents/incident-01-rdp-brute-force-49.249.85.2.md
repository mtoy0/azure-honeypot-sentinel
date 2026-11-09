# Incident 01: RDP Credential Spray from 49.249.85.2

**Date/Time detected:** Sept 29, 2026 (first 24 hours of honeypot exposure)
**Detection method:** Manual threat hunting with KQL in `law-honeypot` (no automated analytics rule yet)
**Severity:** Medium. High volume, but no successful access.
**Asset:** `vm-honeypot` (Windows Server 2022, public IP, RDP open to the internet on purpose)

## 1. Preparation
- Security event logs forwarded through Azure Monitor Agent → `dcr-honeypot` → Log Analytics (`law-honeypot`)
- Microsoft Sentinel with the Windows Security Events solution
- KQL queries for failed logons, successful external logons, and GeoIP enrichment ([`kql/`](../kql/))
- Attack dashboard workbook (map, top IPs, failed logons per hour)

## 2. Detection & Analysis
| Item | Finding |
|---|---|
| Source IP | `49.249.85.2` |
| Location (GeoIP) | Hyderabad, India |
| Event | 4625 (failed logon) |
| Volume | **5,364 failed logons in ~24h**, about 95% of all attack traffic on the honeypot |
| Target accounts | A wordlist of usernames: `Administrator` (765), `Manasa`, `Srujana`, `Chandrashekar`, `General`, `for` (561 each), `accounts` (515), `User` (510), `admin` (204), plus others |
| Pattern | The same attempt count across many different usernames, which means an automated credential-spray tool working through a fixed list |
| Successful logon (4624) from this IP? | **No** |

**Context: everyone else.** Nine other IPs made 276 attempts combined. The second-largest was `182.48.206.84` (Bhandup, India) with 183, and the rest made between 1 and 80 attempts each.

**KQL used:**
```kql
// Volume and usernames per attacker
SecurityEvent
| where EventID == 4625
| where IpAddress != "-"
| summarize FailedAttempts = count() by IpAddress, Account
| order by FailedAttempts desc

// Confirm no attacker got in
SecurityEvent
| where EventID == 4624
| where IpAddress != "-" and IpAddress != "127.0.0.1"
| project TimeGenerated, Account, IpAddress, LogonType
```

Evidence: [failed logons by username](../screenshots/04-failed-logons-by-username.png), [GeoIP results](../screenshots/07-geoip-failed-logons.png), [no successful external logons](../screenshots/05-no-successful-external-logons.png), [attack map](../screenshots/08-attack-dashboard-map.png)

## 3. Containment, Eradication & Recovery
**What I did:** No blocking. The VM is a honeypot, so the traffic was left running on purpose to collect data. No credentials were compromised, so there was nothing to eradicate or recover.

**What I'd do on a production server:**
1. Block `49.249.85.2` (and the other attacker IPs) with an NSG deny rule
2. Remove internet-facing RDP. Use Azure Bastion or a VPN, or restrict port 3389 to known admin IPs
3. Check that every account targeted (`Administrator`, `admin`, `User`) has a strong unique password or is disabled or renamed
4. Turn on account lockout and MFA for remote access
5. Search all other systems for the same IP

## 4. Post-Incident Activity
- **Tuning:** Turn the successful-external-logon query into a Sentinel analytics rule (high severity, since any match is a real problem), and add a threshold rule such as "more than 50 failed logons from one IP in 1 hour" (medium severity)
- **Lesson:** Brute force on an exposed RDP port is constant background noise. Detection value comes from catching the one that **succeeds**, not counting the failures.

### Follow-up finding (Oct 1–2): anonymous NTLM logons
A 7-day review of successful logons (4624) on Oct 4 returned 3 events:

| Time (UTC) | Account | Source IP | Logon type | Auth |
|---|---|---|---|---|
| 10/2/2026 9:12 AM | NT AUTHORITY\ANONYMOUS LOGON | 44.251.136.206 | 3 (network) | NTLM |
| 10/1/2026 10:38 AM | NT AUTHORITY\ANONYMOUS LOGON | 142.93.143.8 | 3 (network) | NTLM |
| 10/1/2026 10:38 AM | NT AUTHORITY\ANONYMOUS LOGON | 142.93.143.8 | 3 (network) | NTLM |

**Analysis:** These events log as "successful," but they're anonymous (null) sessions. No username or password was used, and they give no access to user accounts. They're typical of internet scanners probing SMB/RPC, which were reachable because the NSG allowed all ports. **Benign. Not a compromise.**

**Tuning:** Exclude `ANONYMOUS LOGON` from the successful-external-logon alert so it only fires on real accounts:
```kql
SecurityEvent
| where EventID == 4624
| where IpAddress !in ("-", "127.0.0.1", "::1")
| where Account !contains "ANONYMOUS LOGON"
| project TimeGenerated, Account, IpAddress, LogonType
```
Evidence: [anonymous NTLM logons](../screenshots/10-anonymous-ntlm-logons.png)

**Status:** True positive (attack activity); no compromise. Closed.
