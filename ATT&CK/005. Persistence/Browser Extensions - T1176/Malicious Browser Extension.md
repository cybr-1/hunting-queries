---
tags:
  - secops
  - KQL
---
---
**MITRE ATT&CK**
- Tactic: [Persistence](https://attack.mitre.org/tactics/TA0003)
- Technique: [Browser Extensions](https://attack.mitre.org/techniques/T1176)
- Sub Technique: -
- ID: T1176
---
# Hunting Query / Analytic Rule

## Malicious Browser Extension

This query will look up specific browser extension(s) based on the `ExtensionId` value. 

Adversaries may abuse Internet browser extensions to establish persistent access to victim systems. Browser extensions or plugins are small programs that can add functionality and customize aspects of Internet browsers. They can be installed directly or through a browser's app store and generally have access and permissions to everything that the browser can access.

Once the extension is installed, it can browse to websites in the background, steal all information that a user enters into a browser (including credentials), and be used as an installer for a RAT for persistence.

```KQL
let ID = dynamic([
    "", // insert ExtensionId
    ""  // insert ExtensionId
]);
DeviceTvmBrowserExtensions
| where ExtensionId in (ID)
| join kind=inner DeviceInfo on DeviceId
| extend LoggedOnUser = parse_json(LoggedOnUsers).[0].UserName
| extend LoggedOnUserDomain = parse_json(LoggedOnUsers).[0].DomainName
| summarize arg_max(Timestamp, *) by DeviceName
| project Timestamp, DeviceName, DeviceId, ExtensionId, ExtensionName, ExtensionRisk, BrowserName, OnboardingStatus, LoggedOnUser, LoggedOnUserDomain 
```

### How To Obtain `ExtensionId`

A quick KQL query can also be used to obtain all `ExtensionId` installed on a specific device. Just add the device name into the `device` variable on line 1.

```KQL
let device = "";
DeviceTvmBrowserExtensions
| join kind=inner DeviceInfo on DeviceId
| where DeviceName contains device
| summarize arg_max(TimeGenerated, *) by ExtensionId
| project ExtensionId, ExtensionName, ExtensionDescription, ExtensionVersion, ExtensionRisk, BrowserName
| sort by BrowserName
```

