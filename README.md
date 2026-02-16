<img width="1536" height="1024" alt="ChatGPT Image Feb 8, 2026, 04_47_01 PM" src="https://github.com/user-attachments/assets/73c27e50-9c14-4cdd-bd29-2a096e317786" />

# Threat Hunting Case Study  
## Insider-Enabled Data Exfiltration via Living-off-the-Land Techniques  
**Platform:** Microsoft Defender for Endpoint  
**Focus:** End-to-End Threat Hunting using KQL  
**MITRE ATT&CK–Aligned Investigation**

---

## 1. Executive Summary

Azuki Import/Export Trading Co. identified a potential data breach after a competitor undercut a six-year shipping contract by **exactly 3%**, strongly indicating exposure of confidential pricing data. Subsequent intelligence revealed that internal supplier contracts and pricing documents were advertised on underground forums.

A full threat-hunting investigation was conducted using Microsoft Defender for Endpoint telemetry to identify the **initial access vector, attacker behavior, compromised assets, and business impact**.

---

## 2. Environment Context

| Category | Details |
|-------|--------|
| Company | Azuki Import/Export Trading Co. |
| Industry | Shipping Logistics (Japan / SE Asia) |
| Employees | 23 |
| Primary Asset | AZUKI-SL (IT Administrator Workstation) |
| Telemetry | Microsoft Defender for Endpoint |
| Incident Severity | High |
| Likely Incident Type | Data Exfiltration / Insider-Enabled Breach |

---

## 3. Investigation Methodology

The investigation followed a structured threat-hunting lifecycle aligned with the **MITRE ATT&CK framework**:

1. Initial Access  
2. Execution  
3. Discovery  
4. Defense Evasion  
5. Persistence  
6. Command & Control  
7. Credential Access  
8. Collection  
9. Exfiltration  
10. Anti-Forensics  
11. Lateral Movement  
12. Impact  

---


## 5. Initial Access — Suspicious Process Execution

### Objective
Identify malicious execution patterns associated with phishing or script-based compromise.

### Why This Query
Office applications spawning PowerShell or CMD often indicate macro-based phishing or malicious document execution.

### KQL Query
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFileName in ("winword.exe","excel.exe","outlook.exe","powershell.exe","cmd.exe")
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

<img width="1042" height="476" alt="Screenshot 2026-02-02 at 13 18 14" src="https://github.com/user-attachments/assets/5db82894-5cd6-490e-8e66-5997fe02df04" />

### Result

winword.exe spawning powershell.exe

PowerShell executed with ExecutionPolicy Bypass

Strong indicator of malicious document execution

----

### Flag 1 — Initial Access via Remote Desktop
### Objective

Identify unauthorized remote access into the environment.

### KQL Query
```kql
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, ActionType, RemoteIP, LogonType
| order by Timestamp asc
```

<img width="1042" height="476" alt="Screenshot 2026-02-02 at 14 02 10" src="https://github.com/user-attachments/assets/48f49500-8032-41b5-932e-64ed65a18f0c" />

### Result
External source IP identified: 88.97.178.12

----
### Flag 2 — Compromised Account Identification
### Objective

Determine which user account was used during initial access.

### KQL Query
```kql

DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| where RemoteIP == "88.97.178.12"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteIPType, LogonType, AccountName
| order by Timestamp asc

```
<img width="1360" height="278" alt="Screenshot 2026-02-02 at 15 55 11" src="https://github.com/user-attachments/assets/a1ca6353-c0f4-4a7e-a2ec-f5b15bd376a4" />

### Result
Compromised account: kenji.sato

----
### Flag 3 — Discovery: Network Enumeration
### Objective

Detect attacker reconnaissance of the local network.

### KQL Query
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "arp"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, AccountName, FileName, ProcessCommandLine
```
<img width="767" height="215" alt="Screenshot 2026-02-02 at 16 21 43" src="https://github.com/user-attachments/assets/4bdcd630-79a3-47a9-af0e-a5b24c888b57" />

### Result

Network discovery command used: arp -a

-----
### Flag 4 — Defense Evasion: Hidden Malware Staging Directory
### Objective

Identify attacker-created directories used to stage tools and data.

### KQL Query
```kql

DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "attrib"
| where ProcessCommandLine has_any ("+h", "+s")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc

```
### Result

#### Primary staging directory:
C:\ProgramData\WindowsCache


---

### Flag 5 – File Extension Exclusions

**Question:** Number of extensions excluded

```kql
DeviceRegistryEvents
| where DeviceName contains "azuki"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey has_any ("Exclusions", "Extensions")
| project Timestamp, DeviceName, RegistryValueName, RegistryKey
```

**Answer:** `3`

---

### Flag 6 – Folder Path Exclusion

```kql
DeviceRegistryEvents
| where DeviceName contains "azuki"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains "Exclusions"
| where RegistryKey contains "Paths"
| project Timestamp, RegistryValueName
```

**Answer:** `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

---

### Flag 7 – Download Utility Abuse

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("http", "https")
| project Timestamp, FileName, ProcessCommandLine
```

**Answer:** `certutil.exe`

---

## Phase 5 – Persistence

### Flag 8 – Scheduled Task Name

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "schtasks.exe"
| project Timestamp, ProcessCommandLine
```

**Answer:** `Windows Update Check`

---

### Flag 9 – Scheduled Task Target

**Answer:** `C:\ProgramData\WindowsCache\svchost.exe`

---

## Phase 6 – Command & Control

### Flag 10 – C2 Server IP

```kql
DeviceNetworkEvents
| where DeviceName contains "azuki"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessAccountName contains "kenji.sato"
| project Timestamp, RemoteIP, RemotePort
```

**Answer:** `78.141.196.6`

### Flag 11 – C2 Port

**Answer:** `443`

---

## Phase 7 – Credential Access

### Flag 12 – Credential Dumping Tool

```kql
DeviceFileEvents
| where FolderPath contains "WindowsCache"
| where FileName endswith ".exe"
```

**Answer:** `Mm.exe`

---

### Flag 13 – Memory Extraction Module

```kql
DeviceProcessEvents
| where ProcessCommandLine has "sekurlsa::logonpasswords"
```

**Answer:** `sekurlsa::logonpasswords`

---

## Phase 8 – Collection & Exfiltration

### Flag 14 – Data Archive

```kql
DeviceFileEvents
| where FileName endswith ".zip"
```

**Answer:** `Export-data.zip`

---

### Flag 15 – Exfiltration Channel

```kql
DeviceNetworkEvents
| where RemoteUrl contains "discord"
```

**Answer:** `Discord`

---

## Phase 9 – Anti-Forensics & Impact

### Flag 16 – Log Tampering

```kql
DeviceProcessEvents
| where FileName == "wevtutil.exe"
```

**Answer:** `Security`

---

### Flag 17 – Persistence Account

```kql
DeviceProcessEvents
| where ProcessCommandLine has "/add"
```

**Answer:** `Support`

---

### Flag 18 – Malicious Script

```kql
DeviceFileEvents
| where FileName endswith ".ps1"
```

**Answer:** `Wupdate.ps1`

---

### Flag 19 – Lateral Movement Target

**Answer:** `10.1.0.188`

---

### Flag 20 – Lateral Movement Tool

**Answer:** `mstsc.exe`

---










