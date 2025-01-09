---
tags:
  - secops
  - KQL
---
**MITRE ATT&CK**
- Tactic: [Lateral Movement](https://attack.mitre.org/tactics/TA0008)
- Technique: [Remote Services](https://attack.mitre.org/techniques/T1021)
- Sub Technique: [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- ID: T1021.001
---
# User Added to BuiltIn\Remote Desktop Users Group

>[!WARNING]
> All queries should be tested, tuned and checked before live deployment. This is to prevent any automation running off of incorrect alerts, as well as reducing the overall count of false positives.

This rule detects when a user account is added to the "Remote Desktop Users" group on a local machine.  This group grants users the ability to log in to the machine remotely using Remote Desktop Protocol (RDP).

Adding unauthorized accounts to this group could allow attackers to gain remote access to the system and potentially compromise sensitive data or use the machine for malicious purposes.
### Query

```kusto
DeviceEvents
| where ActionType == "UserAccountAddedToLocalGroup"
| extend Details = parse_json(AdditionalFields)
| extend
    GroupName = tostring(Details.GroupName),
    GroupDomainName = tostring(Details.GroupDomainName),
    GroupSid = tostring(Details.GroupSid)
| where GroupSid == "S-1-5-32-555" // BuiltIn\Remote Desktop Users
| join kind=leftouter IdentityInfo on $left.AccountSid == $right.OnPremSid // Join IdentityInfo to retrieve more enriched data
| project-away OnPremSid
| extend InitiatingAccount = strcat(InitiatingProcessAccountDomain, '\\', InitiatingProcessAccountName) 
| extend TargetGroup = strcat(GroupDomainName, '\\', GroupName)
| project 
    Timestamp,
    DeviceId,
    DeviceName,
    TargetGroup,
    TargetAccount = AccountUpn,
    AccountObjectId,
    InitiatingAccount,
    ActionType,
    ReportId
| summarize arg_max(Timestamp, *) by ActionType
```
