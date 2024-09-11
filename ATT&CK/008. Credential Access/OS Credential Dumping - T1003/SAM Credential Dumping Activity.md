---
tags:
  - KQL
---
---
**MITRE ATT&CK**
- Category: Credential Access
- Technique: [OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- Sub Technique: [Security Account Manager](https://attack.mitre.org/techniques/T1003/002/)
- ID: T1003.002
---
# Query

## SAM Credential Dumping Activity

Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored. The SAM is a database file that contains local accounts for the host, typically those found with the `net user` command. Enumerating the SAM database requires SYSTEM level access.

The query will be looking at registry saves, rather than tools such as; Mimikatz, secretsdump.py & pwdumpx.exe

```KQL
DeviceProcessEvents
| where FileName =~ 'reg.exe'
| where ProcessCommandLine has_all('save','hklm','sam')
| project DeviceId, Timestamp, InitiatingProcessId, InitiatingProcessFileName, ProcessId, FileName, ProcessCommandLine
```

