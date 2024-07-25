**MITRE ATT&CK**
- Category: Credential Access
- Technique: [Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- Sub Technique: [Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- ID: T1552.001
---
# Query

## Credential Hunting with findstr

This query will hunt for any processes that have used `findstr` with any of the defined strings. For example `findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml` 

Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.

```KQL
// Define strings, add anymore which could be of use
let sensitiveStrings = dynamic([
    "password",
    "pass",
    "username",
    "user",
    "credentials",
    "creds",
    "administrator",
    "admin",
    "root"
]);
// Locate any events where "findstr" was used to look for the strings defined
DeviceProcessEvents
| where FileName == "findstr.exe"
| where ProcessCommandLine has_any (sensitiveStrings)
| project
    Timestamp,
    ProcessCommandLine,
    FolderPath,
    DeviceName,
    DeviceId,
    AccountUpn,
    AccountSid,
    InitiatingProcessAccountUpn,
    InitiatingProcessAccountSid,
    InitiatingProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    ReportId
