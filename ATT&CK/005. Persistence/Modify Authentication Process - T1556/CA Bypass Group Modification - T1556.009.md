**MITRE ATT&CK**
- Category: Persistence
- Technique: [Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)
- Sub Technique: [Conditional Access Policies](https://attack.mitre.org/techniques/T1556/009/)
- ID: T1556.009
---
# Query

## User Added to CA Policy Bypass Group

This query will hunt for any users added to your conditional access policy bypass groups. If this wasn't expected it could indicate a sign of persistence and allow attackers to circumvent defence measures.

```KQL
// Define and declare CA bypass groups
let bypassGroups = dynamic ([
	"Group 1"
	"Group 2"
	"Group 3"
]);
// Hunt for users added to any of these groups
AuditLogs
| where OperationName == "Add member to group"
| extend TargetGroup = tostring(TargetResources[0].modifiedProperties[1].newValue)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend Target = tostring(TargetResources[0].userPrincipalName) 
| where TargetGroup in (bypassGroups)
| project TimeGenerated, Actor, OperationName, Target, TargetGroup, Result
```