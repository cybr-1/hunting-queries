---
tags:
  - secops
  - KQL
---
---
**MITRE ATT&CK**
- Tactic: [Initial Access](https://attack.mitre.org/tactics/TA0001)
- Technique: [Valid Accounts](https://attack.mitre.org/techniques/T1078)
- Sub Technique: [](https://attack.mitre.org/techniques/)
- ID: -
---
# Hunting Query / Analytic Rule

## Sign In using a consumer VPN

This looks at a list of CIDR ranges from known consumer VPN's such as nordVPN, ExpressVPN etc

```KQL
let VPNRanges = externaldata (IpRange:string) [@'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt'] with (format=txt);
AADSignInEventsBeta
| where isnotempty(IPAddress)
| evaluate ipv4_lookup(VPNRanges, IPAddress, IpRange)
| project Timestamp, AccountUpn, IPAddress, Application, UserAgent, ReportId
```