<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/MattStefano/Threat-Hunting-Scenario-Tor/blob/main/Threat-Hunting-Scenario-Tor-Event-Creation.md) 

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-01-01T02:20:29.2719692Z`. These events began at: `2026-01-01T01:55:05.7371302Z`. 

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-mat"
| where InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-01-01T01:55:05.7371302Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="877" height="316" alt="image" src="https://github.com/user-attachments/assets/46e82cc0-3ffb-4c85-8b73-63759e201c25" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string “tor-browser-windows-x86_64-portable-15.0.3.exe”. Based on the logs returned, at `2026-01-01T01:58:04.7387234Z`, an employee on the “threat-hunt-mat” device ran the file `tor-browser-windows-x86_64-portable-15.0.3.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-mat"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.3.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1217" height="49" alt="image" src="https://github.com/user-attachments/assets/0874c8b4-0734-4960-a32a-d5af6321d550" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2026-01-01T01:58:42.2533917Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

(Side note: The TOR browser is a modified version of Firefox. If, for any reason, it were necessary to demonstrate that it definitely was the TOR browser and not standard Firefox, SHA-256 hashing would be used. Obtaining the same TOR version and comparing hashes would result in a match.)

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-mat"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1087" height="449" alt="image" src="https://github.com/user-attachments/assets/7faf5e48-e17d-44ea-b43d-17f57739fb75" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-01-01T02:01:38.8432539Z`, an employee on the “threat-hunt-mat” device successfully established a connection to the remote IP address `80.92.204.251` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.
 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-mat"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1230" height="262" alt="image" src="https://github.com/user-attachments/assets/6d004042-5be7-41fa-9ba0-25058a19480c" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-01-01T01:55:05.7371302Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.3.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.3.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-01-01T01:58:04.7387234Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-15.0.3.exe` in silent mode, initiating a background installation of the TOR browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.3.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.3.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-01-01T01:58:42.2533917Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with the TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-01-01T02:01:38.8432539Z`
- **Event:** A network connection to IP `80.92.204.251` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-01-01T02:01:39.3048496Z` - Connected to `94.143.137.213` on port `443`.
  - `2026-01-01T01:59:44.6939046Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-01-01T02:20:29.2719692Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-mat" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-mat` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
