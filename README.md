# Azuki-Series-PORT-of-ENTRY
PORT of ENTRY

🕵️ Threat Hunting Investigation Report

Incident: Confidential Pricing Data Exposure
Company: Azuki Import/Export Trading Co.
Date Range Investigated: 2025-11-19 to 2025-11-20
Telemetry Source: Microsoft Defender for Endpoint (MDE)

📌 Executive Summary

Azuki Import/Export Trading Co. identified indicators of a potential security breach after a competitor undercut a 6-year shipping contract by exactly 3%, strongly suggesting access to confidential pricing data. This suspicion was further validated when supplier contracts and pricing documents appeared on underground forums, indicating unauthorized data exfiltration.

A structured threat hunting investigation was conducted using Microsoft Defender for Endpoint telemetry to identify initial access, attacker behavior, persistence mechanisms, data exfiltration, and impact.

🏢 Environment Context
Attribute	Details
Industry	Shipping & Logistics (Japan / SE Asia)
Employees	23
Primary Host	AZUKI-SL (IT Administrator Workstation)
Security Tooling	Microsoft Defender for Endpoint
🧠 Investigation Methodology

This investigation followed a MITRE ATT&CK–aligned threat hunting lifecycle:

Initial Access

Credential Compromise

Discovery

Defense Evasion

Persistence

Command & Control

Credential Access

Collection

Exfiltration

Anti-Forensics

Lateral Movement

Impact

Each phase includes:

Objective

Detection logic (KQL)

Observed results

Conclusion

1️⃣ Initial Access – Suspicious Process Execution
🎯 Objective

Identify how the attacker gained initial access to the environment.

🔎 Detection Logic (KQL)
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFileName in ("winword.exe","excel.exe","outlook.exe","powershell.exe","cmd.exe")
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc

🧪 Results

winword.exe spawning powershell.exe

PowerShell executed with -ExecutionPolicy Bypass

Command shells launching scripts

✅ Conclusion

The initial access vector is consistent with phishing-based macro execution, leading to PowerShell-based payload delivery.
