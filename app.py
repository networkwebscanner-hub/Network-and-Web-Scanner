from flask import Flask, jsonify, render_template, request, send_from_directory
from scanner import WebScanner
from model_sim import TrafficSimulator
import traceback
import subprocess
import re

def scan_nearby_networks():
    networks = []
    try:
        # Run Windows native netsh command to scan visible wireless networks with BSSID details
        result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, errors='ignore', check=True)
        lines = result.stdout.split('\n')
        current_ssid = None
        current_auth = "Unknown"
        current_enc = "Unknown"
        current_signal = "80%"
        current_channel = "Auto"
        current_radio = "802.11ac"
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("SSID "):
                # Save previous network data
                if current_ssid:
                    networks.append({
                        "ssid": current_ssid,
                        "auth": current_auth,
                        "enc": current_enc,
                        "signal": current_signal,
                        "channel": current_channel,
                        "radio": current_radio,
                        "type": "Wireless"
                    })
                parts = line.split(":", 1)
                if len(parts) > 1:
                    name = parts[1].strip()
                    current_ssid = name if name else "Hidden SSID"
                    current_auth = "Unknown"
                    current_enc = "Unknown"
                    current_signal = "85%"
                    current_channel = "6"
                    current_radio = "802.11ac"
            elif "Authentication" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_auth = parts[1].strip()
            elif "Encryption" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_enc = parts[1].strip()
            elif "Signal" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_signal = parts[1].strip()
            elif "Channel" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_channel = parts[1].strip()
            elif "Radio type" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_radio = parts[1].strip()
                    
        # Append final network parsed
        if current_ssid:
            networks.append({
                "ssid": current_ssid,
                "auth": current_auth,
                "enc": current_enc,
                "signal": current_signal,
                "channel": current_channel,
                "radio": current_radio,
                "type": "Wireless"
            })
    except Exception as e:
        print("WiFi scan subprocess execution skipped:", e)
        
    # Fallback to listing machine netcard interfaces
    if not networks:
        try:
            import psutil
            addrs = psutil.net_if_addrs()
            for name in addrs.keys():
                if "loopback" not in name.lower() and "localhost" not in name.lower():
                    networks.append({
                        "ssid": name,
                        "auth": "Wired/Virtual",
                        "enc": "Secure Link",
                        "signal": "100%",
                        "channel": "Wired",
                        "radio": "GbE Link",
                        "type": "Interface"
                    })
        except Exception as ex:
            print("System network card interfaces query skipped:", ex)
            
    # Default fallbacks
    if not networks:
        networks = [
            {"ssid": "Wi-Fi (Automatic Selector)", "auth": "WPA3", "enc": "AES", "signal": "90%", "channel": "11", "radio": "802.11ax", "type": "Wireless"},
            {"ssid": "Ethernet (Local Connection)", "auth": "Open", "enc": "None", "signal": "100%", "channel": "Wired", "radio": "GbE Link", "type": "Wired"}
        ]
        
    return networks

def get_network_details(interface_type=None):
    details = {
        "ipv4": "127.0.0.1",
        "gateway": "0.0.0.0",
        "dns": "8.8.8.8",
        "mac": "00:00:00:00:00:00"
    }
    try:
        result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, errors='ignore')
        output = result.stdout
        
        # Split on adapters
        sections = re.split(r'\n(?=[a-zA-Z0-9])', output)
        
        best_section = None
        
        # Filter sections by the requested interface type (e.g. WiFi vs Ethernet)
        for section in sections:
            if interface_type:
                if interface_type.lower() == 'wifi':
                    if "wireless" not in section.lower() or "disconnected" in section.lower():
                        continue
                elif interface_type.lower() == 'ethernet':
                    if "ethernet" not in section.lower() or "virtualbox" in section.lower() or "disconnected" in section.lower():
                        continue
            else:
                if "disconnected" in section.lower():
                    continue
            
            # Find an active connected section
            if "IPv4 Address" in section:
                best_section = section
                # Prioritize one with a valid Default Gateway IP
                if "Default Gateway" in section and any(char.isdigit() for char in section.split("Default Gateway")[1].split("\n")[0]):
                    break
        
        # Fallbacks
        if not best_section and interface_type:
            for section in sections:
                if interface_type.lower() == 'wifi' and "wireless" in section.lower():
                    best_section = section
                    break
                elif interface_type.lower() == 'ethernet' and "ethernet" in section.lower():
                    best_section = section
                    break
                    
        if not best_section:
            for section in sections:
                if "IPv4 Address" in section:
                    best_section = section
                    break

        if best_section:
            mac_match = re.search(r'Physical Address[.\s]*:\s*([0-9A-Fa-f-]+)', best_section)
            ip_match = re.search(r'IPv4 Address[.\s]*:\s*([0-9.]+)', best_section)
            gw_match = re.search(r'Default Gateway[.\s]*:\s*([0-9.]+)', best_section)
            
            # DNS Servers block parsing
            dns_servers = []
            if "DNS Servers" in best_section:
                block_text = best_section.split("DNS Servers")[1].split("NetBIOS")[0]
                ips = re.findall(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', block_text)
                if ips:
                    dns_servers = ips
                else:
                    ipv6_ips = re.findall(r'([0-9a-fa-f:]+::[0-9a-fa-f%]+|[0-9a-fa-f:]+)', block_text)
                    if ipv6_ips:
                        dns_servers = [ipv6_ips[0]]
            
            if mac_match: details["mac"] = mac_match.group(1).replace('-', ':').upper()
            if ip_match: details["ipv4"] = ip_match.group(1)
            if gw_match: details["gateway"] = gw_match.group(1)
            if dns_servers:
                details["dns"] = dns_servers[0]
            elif gw_match:
                details["dns"] = gw_match.group(1)
                
    except Exception as e:
        print("Error reading network details:", e)
    return details


app = Flask(__name__)

@app.after_request
def add_cors_headers(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Initialize singletons in-memory
simulator = TrafficSimulator()
scan_history = []

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/<path:filename>')
def serve_root_files(filename):
    return send_from_directory('.', filename)

@app.route('/api/traffic', methods=['GET'])
def get_traffic():
    try:
        # Get live packet feeds (updates stats automatically)
        update_data = simulator.get_live_update()
        return jsonify(update_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    try:
        history = simulator.get_history()
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    try:
        alerts = simulator.get_alerts()
        return jsonify(alerts)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        stats = simulator.get_aggregated_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/model-performance', methods=['GET'])
def get_model_performance():
    try:
        perf = simulator.get_model_performance()
        return jsonify(perf)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def run_scan():
    try:
        data = request.get_json() or {}
        url = data.get('url', '').strip()
        if not url:
            return jsonify({"error": "Please provide a valid website address."}), 400
            
        # Run scanner
        report = WebScanner.scan_website(url)
        if "error" in report:
            return jsonify(report), 400
            
        # Save to scan history in-memory (at the start)
        scan_history.insert(0, report)
        if len(scan_history) > 30:
            scan_history.pop() # limit size
            
        return jsonify(report)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Internal scan error: {str(e)}"}), 500

@app.route('/api/scan-history', methods=['GET'])
def get_scan_history():
    try:
        return jsonify(scan_history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/networks', methods=['GET'])
def get_networks():
    try:
        return jsonify(scan_nearby_networks())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/network-details', methods=['GET'])
def get_details():
    try:
        interface_type = request.args.get('interface', '')
        ssid = request.args.get('ssid', '')
        auth = request.args.get('auth', '')
        enc = request.args.get('enc', '')
        
        # Check connected SSID using Windows native netsh command
        connected_ssid = None
        try:
            res = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, errors='ignore')
            for line in res.stdout.split('\n'):
                if "SSID" in line and "BSSID" not in line:
                    connected_ssid = line.split(":")[1].strip()
                    break
        except Exception:
            pass
            
        # Determine if it's the physically connected network
        is_connected = False
        if ssid and connected_ssid:
            if ssid.lower() == connected_ssid.lower():
                is_connected = True
                
        details = None
        
        # If they select a simulated WiFi network that is not the active one, generate consistent random details
        if interface_type.lower() == 'wifi' and ssid and not is_connected:
            import hashlib
            h = hashlib.md5(ssid.encode('utf-8')).hexdigest()
            ip_third = (int(h[0:2], 16) % 250) + 1
            ip_fourth = (int(h[2:4], 16) % 250) + 2
            mac_p1 = h[4:6].upper()
            mac_p2 = h[6:8].upper()
            mac_p3 = h[8:10].upper()
            dns_provider = ["8.8.4.4", "1.1.1.1", "9.9.9.9", f"192.168.{ip_third}.1"]
            selected_dns = dns_provider[int(h[10:12], 16) % len(dns_provider)]
            
            details = {
                "ipv4": f"192.168.{ip_third}.{ip_fourth}",
                "gateway": f"192.168.{ip_third}.1",
                "dns": selected_dns,
                "mac": f"CC:47:40:{mac_p1}:{mac_p2}:{mac_p3}"
            }
        else:
            details = get_network_details(interface_type)
            
        # Add Security Assessment
        profiles = {
            "Wi-Fi (Automatic Selector)": {
                "level": "Low (Safe)",
                "level_color": "var(--green)",
                "vulnerability": "None detected",
                "threats": "None active"
            },
            "Sentinel_Secure_5G": {
                "level": "Safe (WPA3)",
                "level_color": "var(--green)",
                "vulnerability": "None detected",
                "threats": "None active"
            },
            "vm-26-asus (Nearby)": {
                "level": "Low Risk",
                "level_color": "var(--green)",
                "vulnerability": "Legacy WPA2 protocol",
                "threats": "Brute force risk"
            },
            "CommunityFibre_Guest": {
                "level": "Medium Risk",
                "level_color": "var(--orange)",
                "vulnerability": "Unencrypted open network",
                "threats": "Sniffing, MitM risk"
            },
            "Office_Intel_LAN": {
                "level": "Safe (Wired)",
                "level_color": "var(--green)",
                "vulnerability": "None detected",
                "threats": "None active"
            },
            "Malicious_Pineapple_AP": {
                "level": "Critical Risk",
                "level_color": "var(--red)",
                "vulnerability": "Rogue Access Point (Evil Twin)",
                "threats": "Hijacking, credentials theft"
            },
            "BT-MXFJTQ": {
                "level": "Low Risk",
                "level_color": "var(--green)",
                "vulnerability": "Default pre-shared key",
                "threats": "Key cracking risk"
            }
        }
        
        profile = None
        target_ssid = ssid if ssid else (connected_ssid if connected_ssid else interface_type)
        
        if target_ssid:
            for key, val in profiles.items():
                if key.lower() in target_ssid.lower() or target_ssid.lower() in key.lower():
                    profile = val
                    break
                    
        if not profile:
            is_open = False
            if auth:
                if auth.lower() == 'open' or enc.lower() == 'none':
                    is_open = True
            if is_open:
                profile = {
                    "level": "High Risk",
                    "level_color": "var(--red)",
                    "vulnerability": "Unencrypted Open Connection",
                    "threats": "Traffic sniffing, MitM attacks"
                }
            elif interface_type.lower() == 'ethernet' or interface_type.lower() == 'interface':
                profile = {
                    "level": "Safe (Wired)",
                    "level_color": "var(--green)",
                    "vulnerability": "None detected",
                    "threats": "None active"
                }
            else:
                profile = {
                    "level": "Low Risk",
                    "level_color": "var(--green)",
                    "vulnerability": "WPA2 Pre-Shared Key",
                    "threats": "Password cracking susceptibility"
                }
                
        details["security"] = profile
        return jsonify(details)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/select-network', methods=['POST'])
def select_network():
    try:
        data = request.get_json() or {}
        ssid = data.get('ssid', '')
        auth = data.get('auth', '')
        enc = data.get('enc', '')
        
        # Increase anomaly levels if the user chooses an unencrypted network
        if auth == 'Open' or enc == 'None':
            simulator.anomaly_threshold = 0.65  # 35% threats
        else:
            simulator.anomaly_threshold = 0.85  # 15% threats
            
        return jsonify({"status": "success", "monitoring": ssid, "anomaly_threshold": simulator.anomaly_threshold})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================================================
# LOCAL STABLE USER DATABASE & AUTHENTICATION (REPLACES GOOGLE SHEETS)
# ==========================================================================
import json
import os
import random
import string
import hashlib
from datetime import datetime, timedelta

DB_FILE = 'users_db.json'

def load_db():
    if not os.path.exists(DB_FILE):
        default_data = {
            "users": [
                {
                    "userCode": "123456",
                    "name": "Agent Johnson",
                    "email": "johnson@sentinel.net",
                    "passwordHash": hashlib.sha256(("admin123" + "123456").encode('utf-8')).hexdigest(),
                    "otp": "",
                    "otpExpiry": "",
                    "status": "ACTIVE",
                    "createdAt": datetime.utcnow().isoformat() + "Z"
                }
            ],
            "activities": [
                { "time": "05:12 PM", "user": "Operator", "action": "Executed traffic scan check" },
                { "time": "02:18 PM", "user": "System", "action": "Firewall segment WAN optimized" },
                { "time": "09:41 AM", "user": "Operator", "action": "Authorized session established" }
            ],
            "visitorStats": [120, 180, 140, 290, 310, 480, 390, 520, 580, 510, 720, 891]
        }
        save_db(default_data)
        return default_data
    try:
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {"users": [], "activities": [], "visitorStats": []}

def save_db(data):
    try:
        with open(DB_FILE, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print("Database save error:", e)

def hash_password(password, salt):
    combined = password + salt
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()

@app.route('/api/backend', methods=['POST'])
def local_backend():
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({"success": False, "error": "Invalid request payload format."})

    action = payload.get("action")
    db = load_db()
    users = db.get("users", [])
    
    if action == "loginUser":
        login_input = payload.get("loginInput", "").strip()
        password = payload.get("password", "")
        user_code = payload.get("userCode", "").strip()
        
        user = next((u for u in users if u["userCode"] == user_code), None)
        if not user:
            return jsonify({"success": False, "error": "Invalid credentials or User Code."})
            
        hashed = hash_password(password, user_code)
        if user["passwordHash"] != hashed:
            return jsonify({"success": False, "error": "Invalid credentials or User Code."})
            
        if user["status"] != "ACTIVE":
            return jsonify({"success": False, "error": "Verification incomplete. Status: " + user["status"]})
            
        db.setdefault("activities", []).insert(0, {
            "time": datetime.now().strftime("%I:%M %p"),
            "user": "Operator",
            "action": f"User login established: {user['name']}"
        })
        save_db(db)
        
        return jsonify({
            "success": True,
            "name": user["name"],
            "email": user["email"],
            "userCode": user["userCode"]
        })
        
    elif action == "registerInit":
        name = payload.get("name", "").strip()
        email = payload.get("email", "").strip()
        
        if next((u for u in users if u["email"].lower() == email.lower()), None):
            return jsonify({"success": False, "error": "Email address already registered."})
            
        user_code = "".join(random.choices(string.digits, k=6))
        while next((u for u in users if u["userCode"] == user_code), None):
            user_code = "".join(random.choices(string.digits, k=6))
            
        new_user = {
            "userCode": user_code,
            "name": name,
            "email": email,
            "passwordHash": "",
            "otp": "",
            "otpExpiry": "",
            "status": "PENDING_PASSWORD",
            "createdAt": datetime.utcnow().isoformat() + "Z"
        }
        users.append(new_user)
        save_db(db)
        return jsonify({"success": True, "userCode": user_code})
        
    elif action == "registerComplete":
        user_code = payload.get("userCode", "").strip()
        password = payload.get("password", "")
        
        user = next((u for u in users if u["userCode"] == user_code), None)
        if not user:
            return jsonify({"success": False, "error": "User profile not found."})
            
        hashed = hash_password(password, user_code)
        otp = "".join(random.choices(string.digits, k=6))
        otp_expiry = (datetime.utcnow() + timedelta(minutes=10)).isoformat() + "Z"
        
        user["passwordHash"] = hashed
        user["otp"] = otp
        user["otpExpiry"] = otp_expiry
        user["status"] = "PENDING_OTP"
        
        db.setdefault("activities", []).insert(0, {
            "time": datetime.now().strftime("%I:%M %p"),
            "user": "Operator",
            "action": f"OTP verification code sent for {user['name']}"
        })
        save_db(db)
        
        print(f"\n==========================================")
        print(f" OTP CODE FOR {user['name']} ({user_code}): {otp} ")
        print(f"==========================================\n")
        
        return jsonify({"success": True, "otp": otp})
        
    elif action == "verifyOTP":
        user_code = payload.get("userCode", "").strip()
        otp = payload.get("otp", "").strip()
        
        user = next((u for u in users if u["userCode"] == user_code), None)
        if not user:
            return jsonify({"success": False, "error": "User profile not found."})
            
        if user["otp"] != otp:
            return jsonify({"success": False, "error": "Incorrect verification code."})
            
        user["status"] = "ACTIVE"
        user["otp"] = ""
        user["otpExpiry"] = ""
        
        db.setdefault("activities", []).insert(0, {
            "time": datetime.now().strftime("%I:%M %p"),
            "user": "Operator",
            "action": f"Account verification completed for {user['name']}"
        })
        save_db(db)
        return jsonify({"success": True})
        
    elif action == "resendOTP":
        user_code = payload.get("userCode", "").strip()
        user = next((u for u in users if u["userCode"] == user_code), None)
        if not user:
            return jsonify({"success": False, "error": "User profile not found."})
            
        otp = "".join(random.choices(string.digits, k=6))
        otp_expiry = (datetime.utcnow() + timedelta(minutes=10)).isoformat() + "Z"
        
        user["otp"] = otp
        user["otpExpiry"] = otp_expiry
        save_db(db)
        
        print(f"\n==========================================")
        print(f" RESENT OTP CODE FOR {user['name']} ({user_code}): {otp} ")
        print(f"==========================================\n")
        return jsonify({"success": True, "otp": otp})
        
    elif action == "forgotInit":
        email = payload.get("email", "").strip()
        user = next((u for u in users if u["email"].lower() == email.lower()), None)
        if not user:
            return jsonify({"success": False, "error": "Email address not registered."})
            
        otp = "".join(random.choices(string.digits, k=6))
        otp_expiry = (datetime.utcnow() + timedelta(minutes=10)).isoformat() + "Z"
        
        user["otp"] = otp
        user["otpExpiry"] = otp_expiry
        save_db(db)
        
        print(f"\n==========================================")
        print(f" RECOVERY OTP CODE FOR {user['name']}: {otp} ")
        print(f"==========================================\n")
        return jsonify({"success": True, "userCode": user["userCode"]})
        
    elif action == "resendRecoveryOTP":
        user_code = payload.get("userCode", "").strip()
        user = next((u for u in users if u["userCode"] == user_code), None)
        if not user:
            return jsonify({"success": False, "error": "User profile not found."})
            
        otp = "".join(random.choices(string.digits, k=6))
        otp_expiry = (datetime.utcnow() + timedelta(minutes=10)).isoformat() + "Z"
        
        user["otp"] = otp
        user["otpExpiry"] = otp_expiry
        save_db(db)
        
        print(f"\n==========================================")
        print(f" RESENT RECOVERY OTP CODE: {otp} ")
        print(f"==========================================\n")
        return jsonify({"success": True})
        
    elif action == "forgotVerifyOTP":
        user_code = payload.get("userCode", "").strip()
        otp = payload.get("otp", "").strip()
        
        user = next((u for u in users if u["userCode"] == user_code), None)
        if not user:
            return jsonify({"success": False, "error": "User profile not found."})
            
        if user["otp"] != otp:
            return jsonify({"success": False, "error": "Incorrect verification code."})
            
        return jsonify({"success": True})
        
    elif action == "forgotResetPassword":
        user_code = payload.get("userCode", "").strip()
        password = payload.get("password", "")
        
        user = next((u for u in users if u["userCode"] == user_code), None)
        if not user:
            return jsonify({"success": False, "error": "User profile not found."})
            
        hashed = hash_password(password, user_code)
        user["passwordHash"] = hashed
        user["otp"] = ""
        user["otpExpiry"] = ""
        user["status"] = "ACTIVE"
        
        db.setdefault("activities", []).insert(0, {
            "time": datetime.now().strftime("%I:%M %p"),
            "user": "System",
            "action": f"Password reset recovery successful for {user['name']}"
        })
        save_db(db)
        return jsonify({"success": True})
        
    elif action == "adminLogin":
        username = payload.get("username", "").strip()
        password = payload.get("password", "")
        if username == "admin" and password == "admin123":
            return jsonify({"success": True, "token": "ADMIN_SECURE_TOKEN_2845"})
        return jsonify({"success": False, "error": "Invalid admin keys."})
        
    elif action == "adminGetUsers":
        token = payload.get("token")
        if token != "ADMIN_SECURE_TOKEN_2845":
            return jsonify({"success": False, "error": "Unauthorized session."})
            
        res_users = []
        for u in users:
            res_users.append({
                "userCode": u["userCode"],
                "name": u["name"],
                "email": u["email"],
                "passwordHash": u["passwordHash"] or "No Hash Set",
                "status": u["status"],
                "createdAt": u["createdAt"]
            })
        return jsonify({"success": True, "users": res_users})
        
    elif action == "adminAddUser":
        token = payload.get("token")
        if token != "ADMIN_SECURE_TOKEN_2845":
            return jsonify({"success": False, "error": "Unauthorized session."})
            
        name = payload.get("name", "").strip()
        email = payload.get("email", "").strip()
        password = payload.get("password", "")
        status = payload.get("status", "ACTIVE")
        
        if next((u for u in users if u["email"].lower() == email.lower()), None):
            return jsonify({"success": False, "error": "Email address already registered."})
            
        user_code = "".join(random.choices(string.digits, k=6))
        while next((u for u in users if u["userCode"] == user_code), None):
            user_code = "".join(random.choices(string.digits, k=6))
            
        hashed = hash_password(password, user_code)
        
        users.append({
            "userCode": user_code,
            "name": name,
            "email": email,
            "passwordHash": hashed,
            "otp": "",
            "otpExpiry": "",
            "status": status,
            "createdAt": datetime.utcnow().isoformat() + "Z"
        })
        
        db.setdefault("activities", []).insert(0, {
            "time": datetime.now().strftime("%I:%M %p"),
            "user": "Admin",
            "action": f"Created user profile row: {name}"
        })
        save_db(db)
        return jsonify({"success": True})
        
    elif action == "adminEditUser":
        token = payload.get("token")
        if token != "ADMIN_SECURE_TOKEN_2845":
            return jsonify({"success": False, "error": "Unauthorized session."})
            
        user_code = payload.get("userCode")
        name = payload.get("name", "").strip()
        email = payload.get("email", "").strip()
        password = payload.get("password", "")
        status = payload.get("status")
        
        user = next((u for u in users if u["userCode"] == user_code), None)
        if not user:
            return jsonify({"success": False, "error": "User profile row not found."})
            
        user["name"] = name
        user["email"] = email
        user["status"] = status
        if password:
            user["passwordHash"] = hash_password(password, user_code)
            
        db.setdefault("activities", []).insert(0, {
            "time": datetime.now().strftime("%I:%M %p"),
            "user": "Admin",
            "action": f"Edited user details: {name}"
        })
        save_db(db)
        return jsonify({"success": True})
        
    elif action == "adminDeleteUser":
        token = payload.get("token")
        if token != "ADMIN_SECURE_TOKEN_2845":
            return jsonify({"success": False, "error": "Unauthorized session."})
            
        user_code = payload.get("userCode")
        user = next((u for u in users if u["userCode"] == user_code), None)
        if not user:
            return jsonify({"success": False, "error": "User profile row not found."})
            
        db["users"] = [u for u in users if u["userCode"] != user_code]
        
        db.setdefault("activities", []).insert(0, {
            "time": datetime.now().strftime("%I:%M %p"),
            "user": "Admin",
            "action": f"Deleted user row: {user['name']}"
        })
        save_db(db)
        return jsonify({"success": True})
        
    elif action == "adminGetStats":
        token = payload.get("token")
        if token != "ADMIN_SECURE_TOKEN_2845":
            return jsonify({"success": False, "error": "Unauthorized session."})
            
        return jsonify({
            "success": True,
            "visitorStats": db.get("visitorStats", [120, 180, 140, 290, 310, 480, 390, 520, 580, 510, 720, 891]),
            "activities": db.get("activities", [])
        })
        
    return jsonify({"success": False, "error": "Invalid backend action."})

if __name__ == '__main__':
    # Running locally
    print("AI-NIDS Server running on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
