---
tags:
  - KQL
---
---
**MITRE ATT&CK**
- Category: Initial Access
- Technique: [Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- Sub Technique: [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
---
# Query

## Breakglass Account Sign-In (T1078.004)

This query will hunt and generate alerts on sign ins coming from breakglass accounts. These accounts should always be monitored. This is to prevent bad actors bypassing security controls and being able to execute anything. [[Breakglass Account Modification|Account modifications]] are also monitored

```KQL
let breakglassAccounts = dynamic([
    "<breakglass account 1>",
    "<breakglass account 2>"
    ]);
AADSignInEventsBeta
| where AccountUpn in (breakglassAccounts)
| project Timestamp, Application, IPAddress, Country, AccountUpn,ReportId
```

