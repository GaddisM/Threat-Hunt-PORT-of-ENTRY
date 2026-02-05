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









