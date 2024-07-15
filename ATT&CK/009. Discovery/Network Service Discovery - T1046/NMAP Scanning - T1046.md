- Category: Discovery
- Technique: [Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- Sub Technique: -
- ID: T1046
---
# Query

## Active NMAP/Zenmap Scanning

This query will hunt for any endpoint that executes the NMAP/Zenmap executable.

**THIS WILL ONLY HUNT FOR THE PROGRAMME RUNNING NOT NETWORK TRAFFIC, FOR EXAMPLE, A MACHINE MAY BE COMPROMISED AND AN ATTACKER IS LEVERAGING IT TO USE NMAP.**

### NMAP
```KQL
DeviceProcessEvents
| where Timestamp >= ago(30d) // Setting timeframe for query
| where InitiatingProcessCommandLine contains "cmd" and ProcessCommandLine contains "nmap" // Looking for NMAP usage via Command line
// Filtering out
    | where ProcessCommandLine != "cvtres.exe" // This process has created temp directories with "nmap" in the string
| project InitiatingProcessCommandLine, ProcessCommandLine, DeviceName, AccountUpn, DeviceId, Timestamp, ReportId
```

### Zenmap
```KQL
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where ProcessCommandLine contains "zenmap"
// Filtering out False Positives
    | where ProcessCommandLine != "SenseNdr.exe" // Excluding Sense NDR (Defender's Network Defence module) as it creates directories with random names that can contain "zenmap"
| project InitiatingProcessCommandLine, ProcessCommandLine, DeviceName, AccountUpn, DeviceId, Timestamp, ReportId
```
