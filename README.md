# MITRE ATT&CK Threat Hunting with Wazuh SIEM

## Overview

This project is a hands-on threat hunting lab using **Wazuh SIEM** and a Windows endpoint. The objective was to monitor PowerShell activity, investigate Windows security telemetry, and analyze detected behavior using the **MITRE ATT&CK framework**.

The investigation focused on PowerShell activity that queried Windows security policy information. Wazuh generated an alert for the activity and mapped it to **MITRE ATT&CK T1082 — System Information Discovery** under the **Discovery** tactic.

## Lab Environment

- **SIEM:** Wazuh
- **Endpoint:** Windows
- **Agent Name:** `windows112`
- **Network Details:** Private lab network information is intentionally excluded.
- **Log Source:** `Microsoft-Windows-PowerShell/Operational`

## PowerShell Monitoring

Windows PowerShell Script Block Logging was enabled to capture PowerShell activity. The Wazuh agent was configured to collect the PowerShell Operational event channel.

**PowerShell Event ID:** `4104`

Event ID 4104 provides visibility into PowerShell script blocks and the commands executed on the Windows endpoint, making it useful for security monitoring and threat hunting.

## Threat Hunting Activity

During the investigation, Wazuh detected the following PowerShell activity:

```powershell
secedit /export /cfg $env:\TEMP\\\secpol.cfg; Get-Content $env:\TEMP\\\secpol.cfg | Select-String MinimumPasswordAge; Remove-Item $env:\TEMP\\\secpol.cfg
```

The command exported Windows security policy information to a temporary configuration file, searched the file for the `MinimumPasswordAge` setting, and then removed the temporary file.

This activity was investigated as **discovery-related behavior** because it queried information from the Windows security configuration.

## Wazuh Alert Details

The observed Wazuh alert contained:

- **Rule ID:** `91816`
- **Rule Level:** `4`
- **Rule Description:** `Powershell script querying system environment variables`
- **Event ID:** `4104`
- **MITRE ATT&CK ID:** `T1082`
- **MITRE Tactic:** `Discovery`
- **Technique:** `System Information Discovery`
- **Fired Times:** `4`
- **Agent:** `windows112`

## MITRE ATT&CK Analysis

Wazuh mapped the detected activity to **T1082 — System Information Discovery**, which belongs to the **Discovery** tactic in MITRE ATT&CK.

The mapping helped classify the observed PowerShell activity in the context of discovery behavior. This demonstrates how SIEM telemetry can be investigated and correlated with MITRE ATT&CK techniques during threat hunting.

## Investigation Process

1. Enabled PowerShell Script Block Logging on the Windows endpoint.
2. Configured the Wazuh agent to collect `Microsoft-Windows-PowerShell/Operational` events.
3. Monitored PowerShell Event ID `4104` through Wazuh.
4. Identified the PowerShell activity in the Wazuh alert.
5. Investigated the command and the Windows security policy information it queried.
6. Reviewed the Wazuh rule and its MITRE ATT&CK mapping.
7. Analyzed the activity as **T1082 — System Information Discovery** under the **Discovery** tactic.

## Detection Evidence

Screenshots can be added here after confirming that they contain no private network addresses or other sensitive infrastructure details.

## Skills Demonstrated

- Wazuh SIEM
- Threat Hunting
- PowerShell Monitoring
- Windows Security Monitoring
- Event ID 4104 Analysis
- MITRE ATT&CK Mapping
- Security Log Analysis
- Detection Investigation

## Key Takeaway

This project demonstrates a practical threat hunting workflow using Wazuh to collect PowerShell telemetry, investigate Event ID 4104, analyze discovery-related activity, and map the observed behavior to a MITRE ATT&CK technique.

## Disclaimer

This project was performed in a controlled lab environment for educational and cybersecurity learning purposes. The detected PowerShell activity is documented as observed and investigated behavior and is not presented as proof of a confirmed compromise. Private network addressing and other sensitive infrastructure details are intentionally excluded from this public repository.
