---
tags:
  - secops
  - KQL
---
**MITRE ATT&CK**
- Tactic: [Command and Control](https://attack.mitre.org/tactics/TA0011/)
- Technique: [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)
- Sub Technique: 
- ID: T1071
---
# Query Title

>[!WARNING]-
> All queries should be tested, tuned and checked before live deployment. This is to prevent any automation running off of incorrect alerts, as well as reducing the overall count of false positives.

Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.

Adversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, DNS, or publishing/subscribing. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP.

>[!caution]
>This query does not explicitly indicate on C2 activity. It just alerts on network activity relating to IP's what bad reputation

### Query 

```kusto
let CINS_BadIPs = externaldata (IP:string)[@"http://cinsscore.com/list/ci-badguys.txt"] with ( format="txt"); 
let Threshold = 5; // Define what is suitable 
DeviceNetworkEvents
| where RemoteIP in (CINS_BadIPs) 
| extend Directionality = parse_json(AdditionalFields)["direction"] 
//| where Directionality == "In" // Remove slashes at the start of the line to monitor inbound traffic 
//| where Directionality == "Out" // Remove slashes at the start of the line to monitor outbound traffic 
| summarize arg_max(Timestamp, ReportId), count() by RemoteIP, DeviceName, DeviceId
| where count_ >= Threshold
```

