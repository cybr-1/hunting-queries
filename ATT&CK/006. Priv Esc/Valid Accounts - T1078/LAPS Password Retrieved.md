---
tags:
  - secops
  - KQL
---
---
**MITRE ATT&CK**
- Tactic: [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- Technique: [Valid Accounts](https://attack.mitre.org/techniques/T1078)
- Sub Technique: [Local Accounts](https://attack.mitre.org/techniques/T1078/003/)
- ID: T1078.003
---
# Hunting Query / Analytic Rule

## LAPS Password Retrieved

Although, this activity is logged by Entra ID by default, generating an alert on password retrieval is always a good practice. This is great to enhance attack stories, and entitiy behaviours. 

```KQL
AuditLogs
| extend targetAccount = tostring(TargetResources[0].userPrincipalName) // Extend the targetAccount from the TargetResources field
| extend actorAccount = tostring(InitiatedBy.user.userPrincipalName) // Extent the actorAccount from the InitiatedBy field
| extend targetDevice = tostring(TargetResources[0].displayName)
| where ActivityDisplayName == "Recover device local administrator password"
| project TimeGenerated, Initiated_By=actorAccount, ActivityDisplayName, targetDevice, CorrelationId // Project the important data
```