---
tags:
  - secops
  - KQL
---
**MITRE ATT&CK**
- Tactic: [Persistence](https://attack.mitre.org/tactics/TA0003)
- Technique: [Account Manipulation](https://attack.mitre.org/techniques/T1098)
- Sub Technique: [Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/)
- ID: T1098.007
---
# Query Title

>[!WARNING]
> All queries should be tested, tuned and checked before live deployment. This is to prevent any automation running off of incorrect alerts, as well as reducing the overall count of false positives.

Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permission groups. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials.

In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain. However, account manipulation may also lead to privilege escalation where modifications grant access to additional roles, permissions, or higher-privileged [Valid Accounts](https://attack.mitre.org/techniques/T1078).

A user has been added to the built-in domain group called "Remote Desktop Users" - This group will allow users access to all joined machines via RDP

### Query

```kusto
IdentityDirectoryEvents
| where Application == "Active Directory" // Setting the application this is being used
| where ActionType == "Group Membership changed" // Setting the action that is being performed
| extend ToGroup = tostring(parse_json(AdditionalFields).["TO.GROUP"]) // Defining ToGroup from TO.GROUP in the additional Fields
| extend FromGroup = tostring(parse_json(AdditionalFields).["FROM.GROUP"]) // Defining FromGroup from FROM.GROUP in the additional fields 
| extend Action = iff(isempty(ToGroup), "Remove", "Add") // calculates if the action is Remove or Add
| where Action == "Add" // Only shows additions to the group
| extend GroupModified = iff(isempty(ToGroup), FromGroup, ToGroup) // Specifies the group that was changed
| where GroupModified == "Remote Desktop Users" // Specifing the groups to look for
| project Timestamp, Action, Group_Modified = GroupModified,  TargetAccountDisplayName, TargetAccountUpn,  DC=DestinationDeviceName, Actor=AccountName, ActorDomain=AccountDomain, AdditionalFields, ReportId
```
