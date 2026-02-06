# Victim Environment Setup

> **⚠️ WARNING**: Run this ONLY in an isolated Virtual Machine!

## 1. Prerequisites

Install the required packages:

```bash
pip3 install cryptography requests tk
# Note: 'tk' (Tkinter) is usually installed by default on Python, but you may need 'python3-tk' on Linux.
sudo apt install python3-tk
```

## 2. Configuration

1. Open `ransomware.py`.
2. Find the `ATTACKER_PUBLIC_KEY` section.
3. Paste the content of the `public_key.pem` file (generated on the Attacker machine) between the triple quotes.
4. Ensure `C2_SERVER_URL` points to your Attacker VM's IP address (e.g., `http://192.168.1.5:5000`).

## 3. Creating Dummy Data

Create a directory to test the encryption:

```bash
mkdir ~/test_data
echo "Secret Data" > ~/test_data/file1.txt
```

## 4. Run the Simulation

```bash
python3 ransomware.py
```

The script will encrypt the files in `~/test_data` and display the ransom note.
