---
tags:
  - secops
  - KQL
---

**MITRE ATT&CK**
- Tactic: [Exfiltration](https://attack.mitre.org/tactics/TA0010/)
- Technique: -
- Sub Technique: -  
- ID: TA0010
---
# Hunting Query / Analytic Rule

## SharePoint data exfil to unmanaged device

This query will detect data being downloaded to an unmanaged device from SharePoint and/or OneDrive. Adjust the threshold as needed.

```KQL
let threshold = 50; // Decalring the threshold value of Data
OfficeActivity
| where EventSource == "SharePoint" and OfficeWorkload has_any("SharePoint", "OneDrive") and Operation has_any ("FileDownloaded")
| where UserId !has "app@sharepoint"
| where IsManagedDevice == "false"
| summarize count_distinct_OfficeObjectId=dcount(OfficeObjectId), fileslist=make_set(OfficeObjectId, 10000) by UserId,ClientIP, IsManagedDevice, UserAgent, bin(TimeGenerated, 15m)
| where count_distinct_OfficeObjectId >= threshold
| extend FileSample = iff(array_length(fileslist) == 1, tostring(fileslist[0]), strcat("SeeFilesListField","_", tostring(hash(tostring(fileslist)))))
| extend AccountName = tostring(split(UserId, "@")[0]), AccountUPNSuffix = tostring(split(UserId, "@")[1])
| sort by TimeGenerated desc 
```
