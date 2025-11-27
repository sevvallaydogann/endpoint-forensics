"""
Endpoint Forensics Collector Tool
This script scans for active network connections, persistence mechanisms,
and suspicious files on the host system.
"""

import os
import platform
import datetime
# Standard libraries must be imported before third-party libraries
import psutil

# Import winreg only if running on Windows
if platform.system() == "Windows":
    import winreg

def get_system_info():
    """
    Prints basic system information to identify the host.
    """
    print(f"[INFO] System: {platform.system()} {platform.release()}")
    print(f"[INFO] Hostname: {platform.node()}")
    print(f"[INFO] Scan Time: {datetime.datetime.now()}")
    print("-" * 60)

def scan_network_connections():
    """
    Scans for active 'ESTABLISHED' network connections.
    """
    print("\n[+] Scanning Active Network Connections...")
    print(f"{'PID':<10} {'Status':<15} {'Local Address':<25} {'Remote Address':<25}")
    print("-" * 75)

    suspicious_ports = [4444, 445, 3389, 1337, 6667]

    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == 'ESTABLISHED':
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"

                alert = ""
                if conn.raddr and conn.raddr.port in suspicious_ports:
                    alert = " <!!! SUSPICIOUS PORT DETECTED !!!"

                print(f"{conn.pid:<10} {conn.status:<15} {laddr:<25} {raddr:<25}{alert}")

    except PermissionError:
        print("[ERROR] Permission denied. Please run the script as Administrator/Root.")

def scan_windows_persistence():
    """
    Checks Windows Registry 'Run' keys for persistence mechanisms.
    """
    if platform.system() != "Windows":
        print("\n[!] Persistence scan skipped (Not a Windows system).")
        return

    print("\n[+] Scanning Windows Registry for Persistence...")

    registry_paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    ]

    for reg_path in registry_paths:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ)
            print(f"Checking Path: HKCU\\{reg_path}")

            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    print(f"  > [Startup Item] {name}: {value}")
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except FileNotFoundError:
            print(f"  > Path not found: {reg_path}")
        except OSError as err: # Changed Exception to OSError to fix Pylint error
            print(f"[ERROR] Registry access failed: {err}")

def scan_suspicious_files():
    """
    Scans the temporary directory for suspicious executable files.
    """
    print("\n[+] Scanning Temp Directory for Suspicious Executables...")

    if platform.system() == "Windows":
        temp_dir = os.environ.get('TEMP')
    else:
        temp_dir = "/tmp"

    print(f"Target Directory: {temp_dir}")
    suspicious_extensions = ['.exe', '.bat', '.ps1', '.vbs', '.sh', '.py']

    try:
        found_count = 0
        for root, _, files in os.walk(temp_dir):
            for file in files:
                _, ext = os.path.splitext(file)
                if ext.lower() in suspicious_extensions:
                    print(f"  [!] SUSPICIOUS FILE: {os.path.join(root, file)}")
                    found_count += 1
            break

        if found_count == 0:
            print("  > Clean. No suspicious executables found in the root of Temp.")

    except OSError as err: # Changed Exception to OSError to fix Pylint error
        print(f"[ERROR] File scan failed: {err}")

# --- Main Execution Entry Point ---
if __name__ == "__main__":
    print("========================================")
    print("   ENDPOINT FORENSICS COLLECTOR TOOL    ")
    print("========================================")

    get_system_info()
    scan_network_connections()
    scan_windows_persistence()
    scan_suspicious_files()

    print("\n[INFO] Forensics scan completed.")