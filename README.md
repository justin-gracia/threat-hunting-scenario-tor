<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/justin-gracia/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

I searched the `DeviceFileEvents` table for ANY file that had the string “tor” in it, and discovered what looks like the user “labuser” downloaded a tor installer, and did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “**tor-shopping-list.txt**” on the desktop at **2025-04-01T13:55:34.0439819Z** . These events began at: **2025-04-01T13:43:03.8676592Z**
.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "justin-mde-lab-"  
| where InitiatingProcessAccountName == "labuser"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-04-01T13:43:03.8676592Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/112faa58-97a1-45a0-a5c9-22a9ae78c390)


---

### 2. Searched the `DeviceProcessEvents` Table

I then searched the `DeviceProcessEvents` table for any **ProcessCommandLine** that contained the string “**tor-browser-windows-x86_64-portable-14.0.9.exe**” Based on the logs returned, at **2025-04-01T13:45:05.7317666Z**, a process was created on **justin-mde-lab-** under the "**labuser**" account. The executable **tor-browser-windows-x86_64-portable-14.0.9.exe** was launched from the Downloads folder **(C:\Users\labuser\Downloads\)**. The process was executed with the /s (silent) parameter, suggesting an attempt to install or run the application without user interaction.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "justin-mde-lab-"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.9.exe"
| sort by Timestamp desc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/f7346b5e-4fe1-4322-9aa6-34abb5ae2c0e)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Now that there is confirmation that the Tor browser was installed, I searched the `DeviceProcessEvents` table for any indication that user “**labuser**” actually opened the Tor browser. Based on the logs returned, at **2025-04-01T13:45:58.9663273Z**, the user "**labuser**" on the device "**justin-mde-lab-**" executed a process named **firefox.exe** from the directory **(C:\Users\labuser\Desktop\Tor Browser\Browser\)**. This folder path is consistent with the Tor Browser’s default installation location, indicating that the user likely launched Tor Browser. There were several other instances of **firefox.exe (Tor)** as well as **tor.exe** spawned afterwards.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where FileName has_any ("tor.exe", "firefox.exe", "torbrowser.exe", "start-tor-browser.exe", "tor-browser.exe", "torbrowser-install.exe")
| where DeviceName == "justin-mde-lab-"
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/14dab149-feed-47e4-b7a5-960163ac7dd3)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Finally, I searched the `DeviceNetworkEvents` table for any indication that the user “**labuser**” used the Tor browser to establish a connection using any of the known Tor ports. At **2025-04-01T13:46:32.5394747Z**, the device "**justin-mde-lab-**" successfully established a network connection initiated by the user "**labuser**". The connection was made using the **tor.exe** process, located in **C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe**. The device connected to **remote IP 212.227.127.105** on port **9001**, which is commonly associated with Tor relay traffic. This event further confirms that Tor Browser was actively being used on this device.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "justin-mde-lab-"
| where InitiatingProcessAccountName == "labuser"
| where RemotePort in (9001, 9030, 9050, 9051, 9150, 9151)
| sort by Timestamp desc
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
![image](https://github.com/user-attachments/assets/529f7246-f0b6-41ba-9e1c-526859a384b0)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-01T13:43:03.8676592Z`
- **Event:** The user "labuser" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.9.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-01T13:45:05.7317666Z`
- **Event:** The user "labuser" executed the file `tor-browser-windows-x86_64-portable-14.0.9.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.9.exe /S`
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-01T13:45:58.9663273Z`
- **Event:** User "labuser" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-04-01T13:46:32.5394747Z`
- **Event:** A network connection to IP `212.227.127.105` on port `9001` by user "labuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\labuser\Desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. File Creation - TOR Shopping List

- **Timestamp:** ` 2025-04-01T13:55:34.0439819Z`
- **Event:** The user "labuser" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Desktop\tor-shopping-list.txt`

---

## Summary

The user “labuser” initiated a covert installation of the Tor Browser by downloading and silently executing the installer from the Downloads folder. Shortly afterward, the Tor Browser was launched from the Desktop, and the system recorded a network connection established by the tor.exe process to a known Tor relay on port 9001, confirming its active use. The sequence culminated with the creation of a “tor-shopping-list.txt” file on the Desktop, indicating further engagement with or planning for Tor-related activities.


---

## Response Taken

TOR usage was confirmed on the endpoint `justin-mde-lab-` by the user `labuser`. The device was isolated and the user's direct manager was notified.

---
