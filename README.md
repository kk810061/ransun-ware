# Cerberus Ransomware Simulation 🐕🔥

> **⚠️ DISCALIMER: FOR EDUCATIONAL PURPOSES ONLY. DO NOT USE ON UNAUTHORIZED SYSTEMS.**
> This project demonstrates advanced malware concepts including C2 infrastructure, cryptography, persistence, and social engineering traits.

## 🌟 Key Features

### 💀 Payload Capabilities (`ransomware.py`)

- **Industry-Standard Encryption**: Uses **AES-256-GCM** for file encryption and **RSA-2048** to securely transmit the key to the C2 server.
- **Targeted Destruction**: Encrypts specific file types (`.txt`, `.docx`, `.jpg`, etc.) located in `~/test_data` to ensure safety during testing.
- **Persistent Infection**:
  - Survives reboots by installing itself to Registry (Windows) or Autostart (Linux).
  - Resumes the _same_ victim session ID using a hidden config file (`~/.config/cerberus/cerberus_id.txt`).
- **Psychological Warfare**:
  - **Ragebait GUI**: Fake "Close" button that taunts the user ("LOL access denied").
  - **Voice Threats**: TTS engine announces "System failure imminent" every 30 seconds.
  - **Fake Exfiltration**: simulated data upload progress bar.

### 🕸️ Command & Control (`c2_server.py`)

- **Server-Side Doomsday Timer**: The 72-hour countdown is tracked by the server. Even if the victim shuts down their PC, the timer keeps ticking.
- **Live Dashboard**: View all infected victims, their IP, status, and time remaining.
- **Remote Commands**:
  - `+1H` / `-1H`: Adjust timer.
  - `💀 DOOMSDAY`: Instantly set timer to 1 minute to trigger panic mode.
  - `RELEASE KEY`: Send decryption key to victim.

### 📦 Dropper & Builder (`builder.py`)

- **Dynamic Configuration**: The builder automatically injects the C2 Server's IP address and Public Key into the payload.
- **Stealth Dropper**: `installer.py` mimics an **NVIDIA GeForce Driver Update** (with a convincing fake UI) while silently dropping and executing the ransomware in the background.

---

## 🚀 Setup & Usage

### 1. Start the C2 Server (Attacker Machine)

```bash
cd attacker
pip install -r requirements.txt
python c2_server.py
```

_The server will start on Port 5000. Note your IP address (e.g., `10.0.0.X`)._

### 2. Build the Payload

On the victim machine (or wherever you want to generate the dropper):

```bash
cd victim
python builder.py
```

- Enter the **C2 Server IP** when prompted (e.g., `10.0.0.X`).
- This generates `installer.py` (the dropper).

### 3. Infect the Victim

Transfer `installer.py` to the target machine and run it:

```bash
python installer.py
```

_Ideally, compile this to an EXE/Binary using PyInstaller for maximum realism._

### 4. The Attack Loop

1.  **Fake Installer**: The NVIDIA installer appears.
2.  **Silent Drop**: Ransomware is dropped to `~/.config/` or `%APPDATA%`.
3.  **Lockdown**: The Red/Black Ransomware GUI appears.
4.  **Check-in**: The victim ID appears on the C2 Dashboard.
5.  **Offline Mode**: If C2 is down, it falls back to a local "OFFLINE" mode so you can still test the GUI.

### 5. Recovery (Decryption)

1.  Go to the C2 Dashboard: `http://localhost:5000`.
2.  Find the Victim ID.
3.  Click **RELEASE KEY**.
4.  On the victim machine, the status will change to **"Valid Key Received"**.
5.  Click **DECRYPT FILES**.
6.  Files are restored, persistence is removed, and the malware cleans itself up.

---

## 🛠️ Configuration & Troubleshooting

- **Target Directory**: Currently set to `~/test_data` for safety. Change `TARGET_DIRECTORY` in `ransomware.py` to target other folders.
- **Debug Logs**: If the payload fails, check `~/RANSOMWARE_IMPORT_ERROR.txt` or `~/.config/cerberus/cerberus_log.txt`.
- **Performance**: The Linux "Watchdog" (process killer) is currently **DISABLED** by default to prevent VM freezing. Uncomment `watchdog_loop` in `ransomware.py` to re-enable aggressive process killing.
