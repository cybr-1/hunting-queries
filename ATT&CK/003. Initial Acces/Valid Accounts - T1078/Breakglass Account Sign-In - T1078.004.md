- Category: Initial Access
- Technique: [Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- Sub Technique: [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- ID: T1078.004
---
# Query

## Breakglass Account Sign-In

This query will hunt and generate alerts on sign ins coming from cloud only breakglass accounts. These accounts should always be monitored. This is to prevent bad actors bypassing security controls and being able to execute anything.

Breakglass account modification and audit logs should also be monitored, as if compromised could show signs of persistance, priv esc, defence evasion etc. 

```KQL
// Define breakglass accounts
let breakglassAccounts = dynamic([
    "<breakglass account 1>",
    "<breakglass account 2>"
    ]);
// hunt for sign-ins from these accounts, displaying the relevant info
AADSignInEventsBeta
| where AccountUpn in (breakglassAccounts)
| project Timestamp, Application, IPAddress, Country, AccountUpn,ReportId
```

