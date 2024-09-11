---
tags:
  - secops
  - KQL
---
**MITRE ATT&CK**
- Category: Defence Evasion
- Technique: [Impair Defences](https://attack.mitre.org/techniques/T1562)
- Sub Technique: [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- ID: T1562.001
---
# Hunting Query / Analytic Rule

## Defender for Endpoint Disabled

This query will look for the modifications to the registry value, `DisableAntiSpyware`. This is the value which decides whether microsoft defender is turned off or on. 

```KQL
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where RegistryKey has_any (@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender", @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender")
| where RegistryValueName == "DisableAntiSpyware"
| where RegistryValueType == "Dword"
| where RegistryValueData == 1
```
