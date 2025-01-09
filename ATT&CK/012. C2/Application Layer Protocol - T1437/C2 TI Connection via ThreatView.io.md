---
tags:
  - secops
  - KQL
---
**MITRE ATT&CK**
- Tactic: [Command and Control](https://attack.mitre.org/tactics/TA0011/)
- Technique: [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)
- Sub Technique: - 
- ID: T1071
---
# Query Title

>[!WARNING]
> All queries should be tested, tuned and checked before live deployment. This is to prevent any automation running off of incorrect alerts, as well as reducing the overall count of false positives.

This hunting query will use data from [ThreatView.io](https://threatview.io) to lookup DeviceNetworkEvents and match on any activity, that links the IP and C2 host on the feed. 

Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.

Adversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, DNS, or publishing/subscribing. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP.

### Query

```kusto
// C2 Hunt Feed - Infrastructure hosting Command & Control Servers found during Proactive Hunt by Threatview.io
// #IP,Date of Detection,Host,Protocol,Beacon Config,Comment
let C2Hunt = (externaldata(entry: string,values:dynamic) [@"https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt"]
with (format="txt",ignoreFirstRecord=true))
| where entry !startswith "#"
| extend data = parse_csv(entry)
| extend C2IP = tostring(data[0])
| extend Date = toint(data[1])
| extend C2Host = tostring(data[2])
| extend C2Protocol = tostring(data[3])
| extend C2Beacon = tostring(data[4])
| extend Config = tostring(data[5])
| extend Comment = tostring(data[6])
| project-away ['data']
| where C2IP != ""
;
C2Hunt
| join (DeviceNetworkEvents
| where ActionType =="ConnectionSuccess"
| extend Domain = extract("://(.*)", 1, RemoteUrl)
) 
on ($left.C2IP == $right.RemoteIP) and ($left.C2Host == $right.Domain)
| project Timestamp, C2IP, RemoteIP, DeviceName, RemoteUrl, InitiatingProcessFileName, C2Beacon, C2Host, ReportId, DeviceId
```

#### Change Log

#### v1.0.1
```diff
// C2 Hunt Feed - Infrastructure hosting Command & Control Servers found during Proactive Hunt by Threatview.io
// #IP,Date of Detection,Host,Protocol,Beacon Config,Comment
let C2Hunt = (externaldata(entry: string,values:dynamic) [@"https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt"]
with (format="txt",ignoreFirstRecord=true))
| where entry !startswith "#"
| extend data = parse_csv(entry)
| extend C2IP = tostring(data[0])
| extend Date = toint(data[1])
| extend C2Host = tostring(data[2])
| extend C2Protocol = tostring(data[3])
| extend C2Beacon = tostring(data[4])
| extend Config = tostring(data[5])
| extend Comment = tostring(data[6])
| project-away ['data']
| where C2IP != ""
;
C2Hunt
| join (DeviceNetworkEvents
+ | where ActionType =="ConnectionSuccess"
+ | extend Domain = extract("://(.*)", 1, RemoteUrl)
) 
+ on ($left.C2IP == $right.RemoteIP) and ($left.C2Host == $right.Domain)
| project Timestamp, C2IP, RemoteIP, DeviceName, RemoteUrl, InitiatingProcessFileName, C2Beacon, C2Host, ReportId, DeviceId
```


