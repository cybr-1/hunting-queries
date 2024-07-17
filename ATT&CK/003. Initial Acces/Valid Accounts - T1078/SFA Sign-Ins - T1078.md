**MITRE ATT&CK**
- Category: Initial Access
- Technique: [Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- Sub Technique: - 
- ID: T1078
---
# Query

## SFA Sign-Ins

This query will look for single factor authentication sign in events in your tenant.

```KQL
SigninLogs
  // Query only successfull sign-ins
  | where ResultType == 0
  // Ignore login to Windows & Authentication Broker
  | where AppDisplayName != "Windows Sign In" and AppDisplayName != "Microsoft Authentication Broker"
  // Limit to password only authentication
  | extend authenticationMethod = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod)
  | where authenticationMethod == "Password"
  // Limit to non MFA sign-ins
  | extend authenticationStepRequirement = tostring(parse_json(AuthenticationDetails)[0].authenticationStepRequirement)
  | where AuthenticationRequirement != "multiFactorAuthentication"
  // Add UserName and UserUPNSuffix for strong entity match
  | extend UserName = split(UserPrincipalName,'@',0)[0], UserUPNSuffix = split(UserPrincipalName,'@',1)[0]
  | extend DeviceId = tostring(DeviceDetail.deviceId)
  | extend DeviceOperatingSystem = tostring(DeviceDetail.operatingSystem)
  | project TimeGenerated, UPN=UserPrincipalName, authenticationStepRequirement, AuthenticationRequirement, AuthenticationProtocol, Application=AppDisplayName
  | sort by TimeGenerated desc
```
