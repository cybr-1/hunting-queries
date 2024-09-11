---
tags:
  - KQL
---
---
**MITRE ATT&CK**
- Category: Discovery
- Technique: [Network Service Discovery](https://attack.mitre.org/techniques/T1046/) 
- Sub Technique: 
---
# Query

## Active Network Scanning using NMAP

The query will hunt for any devices executing the NMAP tool via the command line. 

```KQL
DeviceProcessEvents
| where Timestamp >= ago(30d) // Setting timeframe for query
| where InitiatingProcessCommandLine contains "cmd" and ProcessCommandLine contains "nmap" // Looking for NMAP usage via Command line
// Filtering out
    | where DeviceName != "DT-LAP-89457" // Tommy's Laptop
    | where ProcessCommandLine !contains "cvtres.exe" // This process has created temp directories with "nmap" in the string
| project InitiatingProcessCommandLine, ProcessCommandLine, DeviceName, AccountUpn, DeviceId, Timestamp, ReportId
```

## Active Network Scanning using ZENMAP

The query will hunt for any devices executing the ZENMAP tool via the command line.

```KQL
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where ProcessCommandLine contains "zenmap"
// Filtering out False Positives
    | where DeviceName !contains "DT-LAP-89457" // Tommy's Device
    | where ProcessCommandLine !contains "SenseNdr.exe" // Excluding Sense NDR (Defender's Network Defence module) as it creates directories with random names than can contain "zenmap"
| project InitiatingProcessCommandLine, ProcessCommandLine, DeviceName, AccountUpn, DeviceId, Timestamp, ReportId
```

---
