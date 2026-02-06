# Cerberus: Academic Ransomware Simulation

> **⚠️ WARNING: ACADEMIC USE ONLY**
> This project is for educational and research purposes within a controlled, isolated virtual machine environment. It is designed to demonstrate attack vectors for defensive study. Deploying this on any system without explicit, written permission is illegal and unethical. You are solely responsible for how you use this information.

## Project Overview

"Cerberus" is a multi-stage ransomware simulation designed to demonstrate the lifecycle of a modern cryptographic attack. It showcases:

- **Asymmetric Key Management**: Uses RSA-4096 for secure key exchange.
- **Symmetric File Encryption**: Uses AES-256-GCM for authenticated encryption of victim files.
- **C2 Infrastructure**: A Flask-based Command & Control server for victim management.
- **Anonymous Key Delivery**: Simulation of a "Dead Drop" mechanism (e.g., Pastebin) for Decryption Key release.

## 🛡️ Safety & Isolation Guide (CRITICAL)

Before running ANY part of this project, you must ensure you are working in a safe environment.

### 1. Virtual Machine Isolation

- **Host-Only Networking**: Configure your VMs (Attacker and Victim) to use "Host-Only" or "Internal Network" adapters. DO NOT bridge them to your main LAN or the Internet.
- **Disable Shared Folders**: Ensure no folders are shared between the Guest VM and the Host OS to prevent accidental encryption of host files.
- **Snapshots**: Take a clean snapshot of your Victim VM _before_ running the payload. This allows you to revert the damage instantly.

### 2. File Safety

- **Dummy Data Only**: Only run this simulation against dummy/sacrificial files. NEVER run it on a machine containing actual sensitive or personal data.

## Project Structure

```
/
├── README.md               # You are here
├── attacker/               # C2 Server Infrastructure
│   ├── c2_server.py        # The Command & Control Server
│   ├── public_key.pem      # Generated public key (will be copied to victim)
│   ├── private_key.pem     # Generated private key (stays on server)
│   ├── requirements.txt    # Python dependencies
│   └── README.md           # Instructions for Attackers
└── victim/                 # Victim Payload
    ├── ransomware.py       # The Simulation Script
    └── README.md           # Instructions for Victim Setup
```

## Getting Started

1.  **Set up the Attacker**: Go to `attacker/` and follow the `README.md` to start the C2 server and generate keys.
2.  **Set up the Victim**: Go to `victim/` and follow the `README.md` to configure and run the payload.
