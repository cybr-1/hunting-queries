**MITRE ATT&CK**

- Category: Defence Evasion
- Technique: [Impair Defences](https://attack.mitre.org/techniques/T1562)
- Sub Technique: [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- ID: T1562.001

---

# Hunting Query / Analytic Rule

## Defender for Endpoint Registry Tampering

This query will hunt for any tampering with the Defender for Endpoint registry values. It will exclude system and only look for users accounts performing the action to reduce noise and false positives.  

```KQL
DeviceRegistryEvents
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Advanced Threat Protection"
| where InitiatingProcessAccountName !in ("system","")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName, InitiatingProcessFileName, ActionType, DeviceId,ReportId
| sort by Timestamp desc
```