---
tags:
  - secops
  - KQL
---

**MITRE ATT&CK**
- Tactic: [Discovery](https://attack.mitre.org/tactics/TA0007/)
- Technique: [Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)
- Sub Technique: [Local Groups](https://attack.mitre.org/techniques/T1069/001/)
- ID: T1069.001
---
# Hunting Query / Analytic Rule

## User Added to Local Administrators Group

This query will identify users being added to the `Local Administrators` group via the use of `net`

```KQL
DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where FileName has "net.exe" or FileName has "net1.exe"
| where ProcessCommandLine has_all (@"localgroup", @"administrators", @"/add")
| extend targetAccount = extract(@'(?i)administrators\s+(.*?)\s+/add', 1, ProcessCommandLine)
| where targetAccount != ""
| project Timestamp, actorAccount=AccountName, actorSID=AccountSid, targetAccount, DeviceName, DeviceId, ProcessCommandLine, ReportId
```

