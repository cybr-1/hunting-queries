---
tags:
  - secops
  - KQL
---
---
**MITRE ATT&CK**
- Tactic: [Initial Access](https://attack.mitre.org/tactics/TA0001)
- Technique: [Phishing](https://attack.mitre.org/techniques/T1566)
- Sub Technique: -
- ID: T1566
---
# Hunting Query / Analytic Rule

## Impersonation Email Successfully Delivered

Most if not all email security vendors will cover some aspect of impersonation protection, whether that is for all staff or just a select few HVT's for the organisation. However there can always be gaps, or ones that get through. This query will use data from the Microsoft Defender for Identity (MDI) table, `IdentityInfo`, and the Microsoft Defender for Office 365 table, `EmailEvents`, to lookup any discrepancies between the sender display name and sender mail from address, compared to the details stored in Active Directory.

```KQL
// define which users to cover
let managers = dynamic([""]); // Quick way to group senior users who have a common manager, such as a CEO
let departments = dynamic([""]); // Quick way to identify users based off of their department, such as Finance
let users = dynamic ([ ""]); // Any additional users not included in the above
//
// lookup the AD user account for the users defined
let protectedUsers = IdentityInfo
| where Manager in (managers) or Department in (departments) or AccountDisplayName in (users)
| project AccountDisplayName, EmailAddress;
//
// define domains to allow impersonation and allowed senders
let allowedDomains = dynamic([ "" ]); // allowed domains to impersonate, for example, sharepointonline.com
let allowedSenders = dynamic([ ""]); // allowed senders, could be personal emails.
//
// lookup sender display name and email address discrepencies
EmailEvents
| where Timestamp >= ago(48h)
| join kind=inner (
    protectedUsers
) on $left.SenderDisplayName == $right.AccountDisplayName
| where SenderFromAddress != EmailAddress and SenderDisplayName == AccountDisplayName
| where EmailDirection contains "Inbound"
| where LatestDeliveryLocation contains "Inbox"
| where SenderMailFromDomain !in (allowedDomains)
| where SenderMailFromAddress !in (allowedSenders)
| summarize arg_max(Timestamp, *) by NetworkMessageId
```