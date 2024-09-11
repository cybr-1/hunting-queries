---
tags:
  - KQL
---
---
**MITRE ATT&CK**
- Category: Credential Access
- Technique: [Brute Force](https://attack.mitre.org/techniques/T1110/)
- Sub Technique: - 
- ID: T1110
---
# Query

## Suspected Brute Force Attack

This query will use the `IdentityLogonEvents` table to look at account logon activity on-prem. It will reference accounts with `WrongPassword` logon failures, linked to brute forcing, and then will lookup when the first successful sign in occurred. 

```KQL
// Get users with 50+ WrongPassword logons & record IP addresses
let failedLogons = IdentityLogonEvents
| where FailureReason == @"WrongPassword"
| where ActionType == @"LogonFailed"
| where AccountUpn != ""
| where IPAddress != ""
| summarize failureCount = count(), failureIPs = make_set(IPAddress) by AccountUpn
| where failureCount > 25; // Change this to whatever suits, you & your team. The lower the value the more FP's you may have
// Get the users first successful sign in
let firstSuccess = IdentityLogonEvents
| where AccountUpn in ((failedLogons | project AccountUpn))
| where ActionType == @"LogonSuccess"
| summarize firstSuccessTime = min(TimeGenerated) by AccountUpn; // Locate the earliest successful logon
// HUNT
IdentityLogonEvents
| where AccountUpn in ((firstSuccess | project AccountUpn))
| where ActionType == @"LogonSuccess"
| join kind=inner (
    firstSuccess
) on AccountUpn
| where Timestamp == firstSuccessTime
| join kind=inner (
    failedLogons
) on AccountUpn
| project AccountUpn, failureCount, failureIPs, Timestamp, IPAddress, ReportId
```
