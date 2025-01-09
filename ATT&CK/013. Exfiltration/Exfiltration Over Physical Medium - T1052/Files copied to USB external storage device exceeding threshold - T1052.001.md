---
tags:
  - secops
  - KQL
---
**MITRE ATT&CK**
- Tactic: [Exfiltration](https://attack.mitre.org/tactics/TA0010/)
- Technique: [Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)
- Sub Technique: [Exfiltration over USB](https://attack.mitre.org/techniques/T1052.001)
- ID: T1052.001
---
# Query Title

>[!WARNING]
> All queries should be tested, tuned and checked before live deployment. This is to prevent any automation running off of incorrect alerts, as well as reducing the overall count of false positives.

Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.

### Query 

```kusto
let Threshold = 50;
// Locating mounted USB mass storage devices
let UsbDriveMount = DeviceEvents
| where ActionType=="UsbDriveMounted"
| extend ParsedFields=parse_json(AdditionalFields)
| project DeviceId, DeviceName, DriveLetter=ParsedFields.DriveLetter, MountTime=Timestamp, ProductName=ParsedFields.ProductName,SerialNumber=ParsedFields.SerialNumber,Manufacturer=ParsedFields.Manufacturer
| order by DeviceId asc, MountTime desc;
// Identifying file copies
let FileEvents = DeviceFileEvents
| where InitiatingProcessAccountName != "system"
| where FolderPath !startswith "C:\\"
| where FolderPath !startswith "\\"
| where FileName !startswith "~"
| project ReportId,DeviceId,InitiatingProcessAccountDomain, InitiatingProcessAccountName,InitiatingProcessAccountUpn, FileName, FolderPath, SHA256, Timestamp, SensitivityLabel, IsAzureInfoProtectionApplied
| order by DeviceId asc, Timestamp desc;
//
FileEvents 
| lookup kind=inner (UsbDriveMount) on DeviceId
| where FolderPath startswith DriveLetter
| where Timestamp >= MountTime
//| partition hint.strategy=native by ReportId ( top 1 by MountTime )
| summarize arg_max(Timestamp, ReportId), files=make_set(FileName), filecount=dcount(FileName) by DeviceId, DeviceName, InitiatingProcessAccountName, tostring(DriveLetter), tostring(ProductName)
| where filecount >= Threshold
```
