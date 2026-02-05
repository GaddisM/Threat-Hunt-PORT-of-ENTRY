# Azuki-Series-PORT-of-ENTRY

🕵️ Threat Hunting Investigation Report

Incident: Confidential Pricing Data Exposure

Company: Azuki Import/Export Trading Co.

Date Range Investigated: 2025-11-19 to 2025-11-20

Telemetry Source: Microsoft Defender for Endpoint (MDE)

------

📌 Executive Summary

Azuki Import/Export Trading Co. identified indicators of a potential security
breach after a competitor undercut a 6-year shipping contract 
by exactly 3%, strongly suggesting access to confidential pricing data. 
This suspicion was further validated when supplier contracts 
and pricing documentsappeared on underground forums, 
indicating unauthorized data exfiltration.


A structured threat hunting investigation was conducted
using Microsoft Defender for Endpoint telemetry to
identify initial access, attacker behavior, 
persistence mechanisms, data exfiltration, and impact.

-----

🏢 Environment Context

Attribute	Details

Industry	Shipping & Logistics (Japan / SE Asia)

Employees	23

Primary Host	AZUKI-SL (IT Administrator Workstation)

Security Tooling	Microsoft Defender for Endpoint

-----

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

-------

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

--------
2️⃣ Initial Access – Remote Desktop Entry Point
🎯 Objective

Identify the remote source used for initial access.

DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteIPType
| order by Timestamp asc

🔎 Result

Remote IP: 88.97.178.12

-------

3️⃣ Compromised Account Identification
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| where RemoteIP == "88.97.178.12"
| project Timestamp, DeviceName, AccountName

🔎 Result

Compromised Account: kenji.sato

-------

4️⃣ Discovery – Network Enumeration
🎯 Objective

Detect reconnaissance activity on the internal network.

DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "arp"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, AccountName, ProcessCommandLine

🔎 Result

Command Used: arp -a

✅ Conclusion

The attacker enumerated network neighbors to identify lateral movement targets.

---------

5️⃣ Defense Evasion – Malware Staging Directory
DeviceProcessEvents
| where ProcessCommandLine has_any ("attrib +h","+s")
| where DeviceName contains "azuki"

🔎 Result

Primary Staging Directory:
C:\ProgramData\WindowsCache

-------

6️⃣ Defense Evasion – Windows Defender Exclusions
File Extension Exclusions
DeviceRegistryEvents
| where RegistryKey has_any ("Exclusions","Extensions")


Extensions Excluded: 3

Folder Path Exclusion
DeviceRegistryEvents
| where RegistryKey contains "Exclusions\\Paths"


Excluded Folder:
C:\Users\KENJI~1.SAT\AppData\Local\Temp

------

7️⃣ Defense Evasion – Living Off the Land (LOLBins)
DeviceProcessEvents
| where ProcessCommandLine has_any ("http","https")

🔎 Result

Abused Binary: certutil.exe

-------

8️⃣ Persistence – Scheduled Task Creation
Task Name
DeviceProcessEvents
| where ProcessCommandLine contains "schtasks.exe"


Task Name: Windows Update Check

Task Target

Executable:
C:\ProgramData\WindowsCache\svchost.exe

--------

9️⃣ Command & Control (C2)
DeviceNetworkEvents
| where InitiatingProcessCommandLine has_any ("svchost.exe","powershell.exe")

Indicator	Value
C2 IP	78.141.196.6
Port	443
🔐 Credential Access – LSASS Dumping
Tool Identified

Filename: Mm.exe

Module Used

Mimikatz Command:
sekurlsa::logonpasswords

📦 Collection – Data Staging
DeviceFileEvents
| where FileName endswith ".zip"


Archive Created: Export-data.zip

📤 Exfiltration
DeviceNetworkEvents
| where RemoteUrl contains "discord"


Exfiltration Channel: Discord

🧹 Anti-Forensics – Log Clearing
DeviceProcessEvents
| where FileName == "wevtutil.exe"


First Log Cleared: Security

🔓 Impact – Backdoor Account Creation
DeviceProcessEvents
| where ProcessCommandLine has "/add"


Backdoor Account: Support

🔁 Lateral Movement
Indicator	Value
Target IP	10.1.0.188
Tool Used	mstsc.exe






┌──────────────────────────────────────────────────────────────────────┐
│                        ATTACK TIMELINE (UTC)                           │
└──────────────────────────────────────────────────────────────────────┘

[ 2025-11-19 ]

│
├─▶ Initial Access
│    ├─ Phishing document opened (winword.exe)
│    ├─ PowerShell launched with ExecutionPolicy Bypass
│    └─ Remote RDP access from 88.97.178.12
│       Account: kenji.sato
│
├─▶ Discovery
│    ├─ Network enumeration using:
│    │     arp -a
│    └─ Identification of internal subnet hosts
│
├─▶ Defense Evasion
│    ├─ Hidden malware staging directory created:
│    │     C:\ProgramData\WindowsCache
│    ├─ Windows Defender exclusions added:
│    │     • 3 file extensions
│    │     • Temp folder exclusion
│    └─ LOLBin abuse:
│          certutil.exe used to download payloads
│
├─▶ Persistence
│    ├─ Scheduled task created:
│    │     Name: "Windows Update Check"
│    └─ Persistence target:
│          C:\ProgramData\WindowsCache\svchost.exe
│
├─▶ Command & Control (C2)
│    ├─ Outbound HTTPS connection established
│    ├─ C2 Server: 78.141.196.6
│    └─ Port: 443
│
├─▶ Credential Access
│    ├─ Credential dumping tool deployed:
│    │     Mm.exe
│    └─ LSASS memory extraction:
│          sekurlsa::logonpasswords
│
├─▶ Collection
│    ├─ Sensitive data staged
│    └─ Archive created:
│          Export-data.zip
│
├─▶ Exfiltration
│    ├─ Data exfiltrated over HTTPS
│    └─ Cloud service abused:
│          Discord
│
├─▶ Anti-Forensics
│    ├─ Event logs cleared using wevtutil.exe
│    └─ First log removed:
│          Security
│
├─▶ Impact
│    ├─ Backdoor administrator account created:
│    │     Username: Support
│    └─ Environment left with persistent access
│
└─▶ Lateral Movement
     ├─ Target system identified:
     │     10.1.0.188
     └─ Remote access tool used:
           mstsc.exe

