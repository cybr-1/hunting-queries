**MITRE ATT&CK**
- Category: Persistence
- Technique: [Create Account](https://attack.mitre.org/techniques/T1136/)
- Sub Technique: [Local Account](https://attack.mitre.org/techniques/T1136/001/)
- ID: T1136.001
---
# Query

## Local Account Created

This query will hunt for local accounts created on endpoints and servers. For example sysadmins often create local accounts to run specific tasks on the device, where the use of an gMSA or MSA would be more suitable. However, as quoted from the definition in ATT&CK, "Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service."

> [!WARNING]
> This may bring up false positives a lot of the time, but it is always good to have this alert to help enrich attack stories

```KQL
// Collect all Server IDs for filter
let Servers = DeviceInfo
     | where DeviceType == 'Server'
     | summarize make_set(DeviceId);
// Collect all Workstation IDs for filter
let WorkStations = DeviceInfo
     | where DeviceType == 'Workstation'
     | summarize make_set(DeviceId);
DeviceEvents
| where ActionType == 'UserAccountCreated'
// Extract the DeviceName without the domain name
| extend DeviceNameWithoutDomain = extract(@'(.*?)\.', 1, DeviceName),
// Filter on local additions, then the AccountDomain is equal on the
DeviceName
| where AccountDomain =~ DeviceNameWithoutDomain
// Add any filters or exclusions here
// Add DeviceType
| extend DeviceType = iff(DeviceId in (WorkStations), 'WorkStation', iff(DeviceId in (Servers), 'Server', 'Other'))
| project Timestamp, DeviceName, DeviceType, ActionType, AccountDomain, AccountName, AccountSid, DeviceId, ReportId
```
