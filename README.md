# 💻 Digital Forensics Mini-Case – Malware-Based Investigation

A mini malware investigation focused on detecting malicious activity, persistence behavior, and Indicators of Compromise (IOCs) using open-source sandbox data.

---

## 🧪 Summary

This investigation involved behavioral analysis of a malware sample using VirusTotal’s sandbox. The malware attempted outbound communication, executed suspicious processes, dropped executable files, and made registry changes commonly linked to persistence mechanisms.

---

## 🧠 Key Findings

- **C2 Activity**: Outbound TCP connection to `46.19.141.202:8808 (go.gets-it.net)` suggests potential command-and-control behavior.
- **Masqueraded Process**: Launched a suspicious updater from a non-standard directory, mimicking legitimate software to avoid detection.
- **Dropped Files**:
  - `C:\Program Files (x86)\Google\GoogleUpdater\137.0.7129.0\updater.exe`
  - `C:\Program Files (x86)\Google\GoogleUpdater\137.0.7129.0\uninstall.cmd`
- **Registry Persistence Attempts**:
  - `HKCU\Software\Classes\Local Settings\MuiCache\79\52C64B7E\@%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe,-124`
  - `HKCU\Software\Classes\Local Settings\MuiCache\79\52C64B7E\@%SystemRoot%\system32\dnsapi.dll,-103`

---

## 🧾 Indicators of Compromise (IOCs)

| Type             | Value                                                                 |
|------------------|-----------------------------------------------------------------------|
| IP Address       | 46.19.141.202                                                         |
| Contacted Domain | go.gets-it.net                                                        |
| File Dropped     | C:\Program Files (x86)\Google\GoogleUpdater\137.0.7129.0\updater.exe  |
| File Dropped     | C:\Program Files (x86)\Google\GoogleUpdater\137.0.7129.0\uninstall.cmd|
| Registry Key     | HKCU\Software\Classes\Local Settings\MuiCache\...\powershell.exe      |
| Registry Key     | HKCU\Software\Classes\Local Settings\MuiCache\...\dnsapi.dll          |
| Process Path     | C:\Program Files\Google2088_1896458955\bin\updater.exe                |
| Process Command  | --update --system --enable-logging                                    |

---

## 🎯 MITRE ATT&CK Mapping

| Tactic               | Technique ID | Technique Name                           | Observation                                                                 |
|----------------------|--------------|------------------------------------------|------------------------------------------------------------------------------|
| Command and Control  | T1071.001    | Application Layer Protocol: Web Protocols | Outbound C2 connection to `go.gets-it.net` over TCP port 8808               |
| Persistence          | T1547.001    | Registry Run Keys / Startup Folder        | Registry changes made for PowerShell and DNSAPI DLL paths                   |
| Defense Evasion      | T1036.005    | Masquerading: Match Legitimate Name or Location | Suspicious updater process mimicking Google in a non-standard directory |
| Execution            | T1204.002    | User Execution: Malicious File            | Executable dropped to launch updater with suspicious flags                  |

---

## 🛡️ Remediation & Defensive Recommendations

1. **Block Known IOCs**  
   - Block the domain `go.gets-it.net` and IP address `46.19.141.202` at the network firewall and DNS level.
   - Add file hashes of the dropped executables to endpoint protection or AV blocklists.

2. **Registry Monitoring & Cleanup**  
   - Monitor and alert on unusual changes to `HKCU\Software\Classes\Local Settings\MuiCache`.
   - Manually remove unauthorized persistence entries referencing `powershell.exe` and `dnsapi.dll`.

3. **Endpoint Protection**  
   - Deploy endpoint detection and response (EDR) tools capable of flagging unauthorized startup programs and masquerading executables.

4. **Process & File Auditing**  
   - Flag unsigned executables and non-standard installs in system directories like `C:\Program Files\Google2088_...`.

5. **User Awareness**  
   - Educate users on avoiding unknown downloads and understanding suspicious file names or unusual application prompts.

6. **MITRE ATT&CK-Based Detection**  
   - Align SIEM alerts with mapped MITRE techniques:
     - T1071.001 (C2)
     - T1547.001 (Persistence)
     - T1036.005 (Masquerading)
     - T1204.002 (Execution)

7. **Forensic Readiness**  
   - Ensure log retention and centralized log collection (e.g., Sentinel) for future forensic investigations.

---

## 🛠 Tools Used

- [VirusTotal](https://www.virustotal.com/)
- [Any.Run](https://any.run/)
- Wireshark
- MITRE ATT&CK

---

## 📂 Deliverables (In Progress)

- Malware behavior summary (✅)
- IOC table (✅)
- MITRE ATT&CK mapping (✅)
- Report & screenshots folder (✅)
