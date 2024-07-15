- Category: Initial Access
- Technique: [Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- Sub Technique: [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- ID: T1078.004
---
# Query

## Breakglass Account Sign-In 

This query will look for any modifications to the breakglass accounts listed.

```KQL
// Declare the breakglass accounts
let breakglassAccounts = dynamic([
    "breakglass account 0",
    "breakglass account 1"
    ]);
// Query  
AuditLogs
| extend targetAccount = tostring(TargetResources[0].userPrincipalName) // Extend the targetAccount from the TargetResources field
| extend actorAccount = tostring(InitiatedBy.user.userPrincipalName) // Extent the actorAccount from the InitiatedBy field
| extend modifedProperties = tostring(TargetResources[0].modifiedProperties)
| where targetAccount in (breakglassAccounts) // Filter the logs to look for the breakglass accounts
| project TimeGenerated, Breakglass_Account=targetAccount, Initiated_By=actorAccount, ActivityDisplayName, Identity,modifedProperties, CorrelationId // Project the importand data
```

