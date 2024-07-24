**MITRE ATT&CK**
- Category: Persistence
- Technique: [Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- Sub Technique: -
- ID: T1098
---
# Query

## User Added to Privileged Group (AD)

This query will lookup data in which users were added to privileged groups that are defined. It is good practice to monitor the obvious groups like domain admin, but also those groups which include access to sensitive data also. 

```KQL
// Define which groups need to checked
let targetGroups = dynamic([
    "group 1",
    "group 2"
]);
// HUNT!
IdentityDirectoryEvents
| where Application == "Active Directory"
| where ActionType == "Group Membership changed"
// Parsing fields needed
    | extend ToGroup = tostring(parse_json(AdditionalFields).["TO.GROUP"]) // Defining ToGroup from TO.GROUP in the additional Fields
    | extend FromGroup = tostring(parse_json(AdditionalFields).["FROM.GROUP"]) // Defining FromGroup from FROM.GROUP in the additional fields
    | extend Action = iff(isempty(ToGroup), "Remove", "Add") // calculates if the action is Remove or Add
    | extend GroupModified = iff(isempty(ToGroup), FromGroup, ToGroup) // Specifies the group that was changed
    | extend Target_Group = tostring(parse_json(AdditionalFields).["TARGET_OBJECT.GROUP"]) // Defining Target object group
// Filter for the groups defined
| where GroupModified has_any (targetGroups)
| project Timestamp, Action, targetGroup = GroupModified,  TargetAccountDisplayName, TargetAccountUpn,  DC=DestinationDeviceName, Actor=AccountUpn, AdditionalFields, ReportId
```