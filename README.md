# Endpoint Forensics Collector

A Python-based "Live Forensics" tool designed to collect volatile data from a running system for Incident Response (IR) analysis.

This tool mimics the behavior of EDR (Endpoint Detection and Response) agents by scanning for active network connections, persistence mechanisms (Registry), and suspicious artifacts in temporary directories.

## Capabilities

1.  **Network Analysis (C2 Detection):**
    * Scans all active (`ESTABLISHED`) network connections using `psutil`.
    * Identifies the Process ID (PID), Local/Remote IPs, and Ports.
    * **Threat Detection:** Automatically flags connections to known suspicious ports (e.g., 4444, 6667, 3389) often used by malware or reverse shells.

2.  **Persistence Analysis (Registry):**
    * *Windows Only:* Inspects the Windows Registry (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`).
    * Detects malware trying to survive system reboots by listing all startup programs.

3.  **Artifact Analysis (File System):**
    * Scans the user's `%TEMP%` directory.
    * Looks for "droppers" or payloads (executable files like `.exe`, `.bat`, `.ps1`) hiding in temporary folders, which is a common malware technique.

## Core Libraries Used

* **`psutil`:** For cross-platform system monitoring (Network & Processes).
* **`winreg`:** For low-level Windows Registry access.
* **`os` & `platform`:** For file system traversal and OS detection.

## Usage

1.  Install the required dependency:
    ```bash
    pip install psutil
    ```
2.  Run the script (Administrator privileges recommended for full visibility):
    ```bash
    python forensics.py
    ```

### Example Output

```text
[+] Scanning Active Network Connections...
PID        Status          Local Address             Remote Address           
---------------------------------------------------------------------------
12960      ESTABLISHED     192.168.1.7:52149         140.82.112.25:443        
6800       ESTABLISHED     192.168.1.7:49434         98.66.133.186:443        
1234       ESTABLISHED     192.168.1.7:5555          10.10.10.10:4444          <!!! SUSPICIOUS PORT DETECTED !!!

[+] Scanning Windows Registry for Persistence...
Checking Path: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  > [Startup Item] Steam: "C:\Program Files (x86)\Steam\steam.exe" -silent
  > [Startup Item] OneDrive: "C:\Users\User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background

[+] Scanning Temp Directory for Suspicious Executables...
Target Directory: C:\Users\User\AppData\Local\Temp
  > Clean. No suspicious executables found in the root of Temp.
