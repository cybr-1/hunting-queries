---
tags:
  - secops
  - KQL
---

**MITRE ATT&CK**
- Tactic: [Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- Technique: [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- Sub Technique: [Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- ID: T1550.002
---
# Hunting Query / Analytic Rule

## Pass the Hash Attack using Invoke-TheHash

Adversaries may "pass the hash" using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash.

This will look for the use of [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash) specifically the the `Invoke-SMBExec` and `Invoke-WMIExec`

```KQL
let pthPS = dynamic([
    "Invoke-SMBExec",
    "Invoke-WMIExec"
]);
DeviceProcessEvents
| where ProcessCommandLine has_any (pthPS)
| project Timestamp, AccountUpn, AccountSid, DeviceName, DeviceId, ProcessCommandLine, ReportId
```
