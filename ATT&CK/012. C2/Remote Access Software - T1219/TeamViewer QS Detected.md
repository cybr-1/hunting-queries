---
tags:
  - secops
  - KQL
---

**MITRE ATT&CK**

- Tactic: [Command and Control](https://attack.mitre.org/tactics/TA0011/)
- Technique: [Remote Access Software](https://attack.mitre.org/techniques/T1219)
- Sub Technique: -
- ID: T1219

---

# Hunting Query / Analytic Rule

## TeamViewer QS Detected

This hunting query will look for any instances of the TeamViewer QS application on the machine. This software doesn't need to be installed onto the machine therefore it is lightweight and can go unrecognised. If you deploy this query on Defender XDR it would be worthwhile to create a custom detection rule which does the following:
- Blocks the file, which will add the SHA1 has to your custom indicators
- Quarantine the file, so it is removed from the system.

```KQL
DeviceFileEvents
| where FileName contains "TeamViewerQS"
| project Timestamp, DeviceId, DeviceName, FileName, SHA1, FolderPath, ActionType, ReportId
```
