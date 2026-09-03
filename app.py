from datetime import datetime
import hashlib
from ids.autoencoder_predict import ensemble_predict, get_autoencoder_metadata
from encryption.adaptive import (adaptive_encrypt, adaptive_decrypt,
                                  select_algorithm, ALGORITHMS,
                                  KYBER_AVAILABLE)
from ids.explainer import explain_prediction
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
import os
import logging
from mfa.otp import generate_secret, get_qr_code, verify_otp
from mfa.fingerprint import generate_fingerprint_hash, verify_fingerprint
from ids.predict import (predict_traffic, get_metadata, 
                          SAMPLE_TRAFFIC, THREAT_LEVELS, 
                          ATTACK_DESCRIPTIONS)

# ── App Setup ──────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# ── Ensure runtime folders exist (fresh filesystem on Render) ──
os.makedirs('logs', exist_ok=True)
os.makedirs('database', exist_ok=True)

# ── Logging Setup ──────────────────────────────────────────
logging.basicConfig(
    filename='logs/security.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)

# NOTE: init_db() is called below at import time (not just under
# __main__) because gunicorn imports this module as app:app and
# never runs the __main__ block — without this, the users/logs/vault
# tables would never get created on Render.

# ── Database Setup ─────────────────────────────────────────
def get_db():
    conn = sqlite3.connect('database/users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            otp_secret TEXT,
            fingerprint_hash TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            ip_address TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            threat_level TEXT DEFAULT 'Normal',
            prev_hash TEXT,
            entry_hash TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,
            category TEXT DEFAULT 'General',
            algorithm TEXT DEFAULT 'AES-256-GCM',
            risk_score INTEGER DEFAULT 0,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()
    print("[+] Database initialized successfully")

GENESIS_HASH = '0' * 64  # fixed starting value for the very first log entry

def compute_entry_hash(prev_hash, username, action, ip, threat_level, timestamp):
    """Fingerprint this entry's content together with the previous entry's
    hash, so editing any past row breaks every hash chained after it."""
    payload = f"{prev_hash}|{username}|{action}|{ip}|{threat_level}|{timestamp}"
    return hashlib.sha256(payload.encode()).hexdigest()

def log_action(username, action, ip, threat_level='Normal'):
    conn = get_db()

    last_row = conn.execute(
        'SELECT entry_hash FROM logs ORDER BY id DESC LIMIT 1'
    ).fetchone()
    prev_hash = last_row['entry_hash'] if last_row and last_row['entry_hash'] else GENESIS_HASH

    timestamp = datetime.now().isoformat()
    entry_hash = compute_entry_hash(prev_hash, username, action, ip, threat_level, timestamp)

    conn.execute(
        '''INSERT INTO logs (username, action, ip_address, threat_level, timestamp, prev_hash, entry_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (username, action, ip, threat_level, timestamp, prev_hash, entry_hash)
    )
    conn.commit()
    conn.close()

def verify_log_integrity():
    """Walk the whole chain and confirm every entry's stored hash still
    matches its content and correctly links to the entry before it."""
    conn = get_db()
    rows = conn.execute('SELECT * FROM logs ORDER BY id ASC').fetchall()
    conn.close()

    expected_prev = GENESIS_HASH
    for row in rows:
        recomputed = compute_entry_hash(
            expected_prev, row['username'], row['action'],
            row['ip_address'], row['threat_level'], row['timestamp']
        )
        if row['prev_hash'] != expected_prev or row['entry_hash'] != recomputed:
            return {
                'intact': False,
                'tampered_at_id': row['id'],
                'total_entries': len(rows),
                'message': f"Chain broken at log entry #{row['id']} \u2014 stored hash no longer matches its content."
            }
        expected_prev = row['entry_hash']

    return {
        'intact': True,
        'total_entries': len(rows),
        'message': f'Chain verified \u2014 all {len(rows)} log entries intact, no tampering detected.'
    }

def get_recent_threat_count(username):
    """Count high/low threats in last 24 hours for this user"""
    conn = get_db()
    count = conn.execute(
        '''SELECT COUNT(*) as c FROM logs 
           WHERE username = ? AND threat_level IN ('High', 'Low')
           AND timestamp >= datetime('now', '-1 day')''',
        (username,)
    ).fetchone()['c']
    conn.close()
    return count

def get_current_threat_level(username):
    """Get most recent threat level for this user"""
    conn = get_db()
    row = conn.execute(
        '''SELECT threat_level FROM logs 
           WHERE username = ? 
           ORDER BY timestamp DESC LIMIT 1''',
        (username,)
    ).fetchone()
    conn.close()
    return row['threat_level'] if row else 'Normal'

init_db()

# ── Routes ─────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('login'))

# ── REGISTER ───────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
        otp_secret = generate_secret()
        fingerprint = generate_fingerprint_hash(username)

        try:
            conn = get_db()
            conn.execute(
                '''INSERT INTO users 
                   (username, email, password, otp_secret, fingerprint_hash) 
                   VALUES (?, ?, ?, ?, ?)''',
                (username, email, hashed_pw, otp_secret, fingerprint)
            )
            conn.commit()
            conn.close()

            logging.info(f"REGISTER SUCCESS | User: {username}")

            # Save secret temporarily to show QR code
            session['setup_user'] = username
            session['setup_secret'] = otp_secret
            session['setup_fingerprint'] = fingerprint

            return redirect(url_for('setup_mfa'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'danger')

    return render_template('register.html')

# ── MFA SETUP PAGE (Shows QR after registration) ───────────
@app.route('/setup-mfa')
def setup_mfa():
    if 'setup_user' not in session:
        return redirect(url_for('register'))
    
    username = session['setup_user']
    secret = session['setup_secret']
    fingerprint = session['setup_fingerprint']
    qr_code = get_qr_code(username, secret)

    return render_template('setup_mfa.html',
                           username=username,
                           secret=secret,
                           qr_code=qr_code,
                           fingerprint=fingerprint)

# ── LOGIN STEP 1: Password ─────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        ip = request.remote_addr

        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password, user['password']):
            # Password OK — move to OTP step
            session['pending_user'] = username
            session['pending_user_id'] = user['id']
            logging.info(f"PASSWORD OK | User: {username} | IP: {ip}")
            log_action(username, 'Password Verified', ip, 'Normal')
            return redirect(url_for('verify_otp_route'))
        else:
            flash('Invalid username or password', 'danger')
            logging.warning(f"LOGIN FAILED | User: {username} | IP: {ip}")
            log_action(username, 'Login Failed', ip, 'Low')

    return render_template('login.html')

# ── LOGIN STEP 2: OTP ──────────────────────────────────────
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp_route():
    if 'pending_user' not in session:
        return redirect(url_for('login'))
    
    username = session['pending_user']
    ip = request.remote_addr

    if request.method == 'POST':
        otp_code = request.form['otp']

        conn = get_db()
        user = conn.execute(
            'SELECT otp_secret FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()

        if user and verify_otp(user['otp_secret'], otp_code):
            session['otp_verified'] = True
            logging.info(f"OTP OK | User: {username} | IP: {ip}")
            log_action(username, 'OTP Verified', ip, 'Normal')
            return redirect(url_for('verify_fingerprint_route'))
        else:
            flash('Invalid OTP code. Try again.', 'danger')
            logging.warning(f"OTP FAILED | User: {username} | IP: {ip}")
            log_action(username, 'OTP Failed', ip, 'High')

    return render_template('otp.html', username=username)

# ── LOGIN STEP 3: Fingerprint ──────────────────────────────
@app.route('/verify-fingerprint', methods=['GET', 'POST'])
def verify_fingerprint_route():
    if 'pending_user' not in session or not session.get('otp_verified'):
        return redirect(url_for('login'))
    
    username = session['pending_user']
    ip = request.remote_addr

    if request.method == 'POST':
        scanned = request.form.get('fingerprint_hash')

        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()

        if user and verify_fingerprint(user['fingerprint_hash'], scanned):
            # ✅ ALL 3 FACTORS PASSED
            session['username'] = username
            session['user_id'] = user['id']
            session.pop('pending_user', None)
            session.pop('otp_verified', None)

            logging.info(f"3FA SUCCESS | User: {username} | IP: {ip}")
            log_action(username, '3-Factor Login Success', ip, 'Normal')
            return redirect(url_for('dashboard'))
        else:
            flash('Fingerprint verification failed.', 'danger')
            logging.warning(f"FINGERPRINT FAILED | User: {username}")
            log_action(username, 'Fingerprint Failed', ip, 'High')

    # Send fingerprint hash to page so JS can send it back on scan
    conn = get_db()
    user = conn.execute(
        'SELECT fingerprint_hash FROM users WHERE username = ?', (username,)
    ).fetchone()
    conn.close()

    return render_template('fingerprint.html',
                           username=username,
                           fingerprint_hash=user['fingerprint_hash'])

# ── DASHBOARD ──────────────────────────────────────────────
@app.route('/admin/users')
def admin_users_route():
    if 'username' not in session:
        return redirect(url_for('login'))
    from flask import jsonify as _jsonify
    conn = get_db()
    users = conn.execute(
        'SELECT id, username, email, created_at FROM users ORDER BY id ASC'
    ).fetchall()
    conn.close()
    return _jsonify({
        'total_users': len(users),
        'users': [dict(u) for u in users]
    })

@app.route('/admin/verify-logs')
def verify_logs_route():
    if 'username' not in session:
        return redirect(url_for('login'))
    from flask import jsonify as _jsonify
    result = verify_log_integrity()
    return _jsonify(result)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user_id = session['user_id']
    conn = get_db()
    
    # Recent logs (last 10)
    recent_logs = conn.execute(
        'SELECT * FROM logs WHERE username = ? ORDER BY timestamp DESC LIMIT 10',
        (username,)
    ).fetchall()
    
    # Total logs count
    total_logs = conn.execute(
        'SELECT COUNT(*) as c FROM logs WHERE username = ?', (username,)
    ).fetchone()['c']
    
    # Vault count
    vault_count = conn.execute(
        'SELECT COUNT(*) as c FROM vault WHERE user_id = ?', (user_id,)
    ).fetchone()['c']
    
    # Threat level breakdown
    threat_stats = conn.execute(
        '''SELECT threat_level, COUNT(*) as count 
           FROM logs WHERE username = ?
           GROUP BY threat_level''', (username,)
    ).fetchall()
    
    stats = {'Normal': 0, 'Low': 0, 'High': 0}
    for row in threat_stats:
        if row['threat_level'] in stats:
            stats[row['threat_level']] = row['count']
    
    # Attack type breakdown
    attack_stats = conn.execute(
        '''SELECT action, COUNT(*) as count 
           FROM logs WHERE action LIKE 'IDS Scan:%' AND username = ?
           GROUP BY action''', (username,)
    ).fetchall()
    
    attack_types = {'DoS': 0, 'Probe': 0, 'R2L': 0, 'U2R': 0, 'Normal': 0}
    for row in attack_stats:
        for atype in attack_types:
            if atype in row['action']:
                attack_types[atype] += row['count']
                break
    
    total_ids_scans = sum(attack_types.values())
    total_threats_detected = sum(v for k, v in attack_types.items() if k != 'Normal')
    
    # Security score
    security_score = 100
    if total_logs > 0:
        threat_ratio = stats['High'] / max(total_logs, 1)
        security_score = max(60, int(100 - (threat_ratio * 100)))
    
    conn.close()
    
    return render_template('dashboard.html', 
                           username=username,
                           logs=recent_logs,
                           total_logs=total_logs,
                           vault_count=vault_count,
                           stats=stats,
                           attack_types=attack_types,
                           total_ids_scans=total_ids_scans,
                           total_threats_detected=total_threats_detected,
                           security_score=security_score)

# ── LOGOUT ─────────────────────────────────────────────────
@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    logging.info(f"LOGOUT | User: {username}")
    log_action(username, 'Logout', request.remote_addr, 'Normal')
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# ── VAULT: List all encrypted items ────────────────────────
@app.route('/vault')
def vault():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = get_db()
    items = conn.execute(
        'SELECT * FROM vault WHERE user_id = ? ORDER BY created_at DESC',
        (user_id,)
    ).fetchall()
    conn.close()
    
    # Decrypt each item using its stored algorithm
    decrypted_items = []
    for item in items:
        algo = item['algorithm'] or 'AES-256-GCM'
        algo_info = ALGORITHMS.get(algo, ALGORITHMS['AES-256-GCM'])
        decrypted_items.append({
            'id': item['id'],
            'title': item['title'],
            'category': item['category'],
            'algorithm': algo,
            'algo_info': algo_info,
            'risk_score': item['risk_score'] or 0,
            'reason': item['reason'] or '',
            'data': adaptive_decrypt(item['encrypted_data'], algo),
            'encrypted_preview': item['encrypted_data'][:40] + '...',
            'created_at': item['created_at']
        })
    
    # Stats for the header
    algo_counts = {}
    for item in decrypted_items:
        algo_counts[item['algorithm']] = algo_counts.get(item['algorithm'], 0) + 1
    
    return render_template('vault.html',
                           username=session['username'],
                           items=decrypted_items,
                           algo_counts=algo_counts,
                           kyber_available=KYBER_AVAILABLE)

# ── VAULT: Add new encrypted item ──────────────────────────
@app.route('/vault/add', methods=['POST'])
def vault_add():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    title = request.form['title']
    data = request.form['data']
    category = request.form.get('category', 'General')
    user_id = session['user_id']
    username = session['username']
    
    # ── Adaptive Algorithm Selection ──
    threat_level = get_current_threat_level(username)
    recent_threats = get_recent_threat_count(username)
    
    decision = select_algorithm(
        category=category,
        threat_level=threat_level,
        data_size=len(data),
        recent_threats=recent_threats
    )
    
    # Encrypt with chosen algorithm
    encrypted = adaptive_encrypt(data, decision['algorithm'])
    
    conn = get_db()
    conn.execute(
        '''INSERT INTO vault 
           (user_id, title, encrypted_data, category, algorithm, risk_score, reason)
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (user_id, title, encrypted, category, 
         decision['algorithm'], decision['risk_score'], decision['reason'])
    )
    conn.commit()
    conn.close()
    
    log_action(username, 
               f"Vault Add: {title} → {decision['algorithm']}",
               request.remote_addr, 'Normal')
    
    flash(f"🔐 Encrypted with {decision['info']['icon']} {decision['algorithm']} — {decision['reason']}", 'success')
    return redirect(url_for('vault'))

# ── VAULT: Delete item ─────────────────────────────────────
@app.route('/vault/delete/<int:item_id>')
def vault_delete(item_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = get_db()
    conn.execute(
        'DELETE FROM vault WHERE id = ? AND user_id = ?',
        (item_id, user_id)
    )
    conn.commit()
    conn.close()
    
    log_action(session['username'], f'Vault Item Deleted',
               request.remote_addr, 'Normal')
    flash('Item deleted.', 'success')
    return redirect(url_for('vault'))

# ── IDS: Dashboard Page ────────────────────────────────────
@app.route('/ids')
def ids_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    metadata = get_metadata()
    ae_metadata = get_autoencoder_metadata()
    
    conn = get_db()
    threat_logs = conn.execute(
        '''SELECT id, username, action, ip_address, timestamp, threat_level
           FROM logs 
           WHERE action LIKE 'IDS%' OR action LIKE 'EXTERNAL%'
           ORDER BY id DESC LIMIT 20'''
    ).fetchall()
    
    threat_counts = conn.execute(
        '''SELECT threat_level, COUNT(*) as count 
           FROM logs 
           WHERE action LIKE 'IDS%' OR action LIKE 'EXTERNAL%'
           GROUP BY threat_level'''
    ).fetchall()
    conn.close()
    
    stats = {'Normal': 0, 'Low': 0, 'High': 0}
    for row in threat_counts:
        if row['threat_level'] in stats:
            stats[row['threat_level']] = row['count']
    
    return render_template('ids.html',
                           username=session['username'],
                           metadata=metadata,
                           ae_metadata=ae_metadata,
                           logs=threat_logs,
                           stats=stats)

# ── IDS: Simulate Attack (AJAX) ────────────────────────────
@app.route('/ids/simulate/<traffic_type>')
def ids_simulate(traffic_type):
    if 'username' not in session:
        return {'error': 'Not authenticated'}, 401
    
    if traffic_type not in SAMPLE_TRAFFIC:
        return {'error': 'Unknown traffic type'}, 400
    
    features = SAMPLE_TRAFFIC[traffic_type]
    
    # Run ENSEMBLE prediction (RF + Autoencoder)
    result = ensemble_predict(features)
    
    # Get SHAP explanation (based on RF prediction)
    try:
        explanation = explain_prediction(features, 
                                          result['rf']['prediction'], 
                                          top_n=5)
    except Exception as e:
        explanation = []
        print(f"SHAP error: {e}")
    
    # Log to database
    action = (f"IDS Scan: {traffic_type} → {result['verdict']} "
              f"(RF: {result['rf']['prediction']}, "
              f"AE: {'Anomaly' if result['ae']['is_anomaly'] else 'Normal'})")
    log_action(session['username'], action,
               request.remote_addr, result['verdict_level'])
    
    if result['verdict_level'] == 'High':
        logging.warning(f"IDS CONFIRMED THREAT | User: {session['username']}")
    elif result['verdict_level'] == 'Low':
        logging.warning(f"IDS SUSPICIOUS | User: {session['username']}")
    
    return {
        'verdict': result['verdict'],
        'verdict_icon': result['verdict_icon'],
        'verdict_level': result['verdict_level'],
        'agreement': result['agreement'],
        'agreement_score': result['agreement_score'],
        'rf': result['rf'],
        'ae': result['ae'],
        'explanation': explanation,
        'traffic_type': traffic_type,
        # Legacy fields for compatibility
        'prediction': result['rf']['prediction'],
        'threat_level': result['verdict_level'],
        'confidence': result['rf']['confidence'],
        'is_attack': result['verdict_level'] != 'Normal'
    }

# ── AUTH LOG ───────────────────────────────────────────────
@app.route('/logs/auth')
def auth_log():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    conn = get_db()
    
    # Get all auth-related logs
    logs = conn.execute(
        '''SELECT * FROM logs 
           WHERE action IN ('Login Success', 'Login Failed', 
                            'Password Verified', 'OTP Verified', 
                            'OTP Failed', 'Fingerprint Failed',
                            '3-Factor Login Success', 'Logout')
              OR action LIKE '%Login%' 
              OR action LIKE '%OTP%'
              OR action LIKE '%Fingerprint%'
              OR action LIKE '%Logout%'
           ORDER BY timestamp DESC LIMIT 100''',
    ).fetchall()
    
    # Stats
    total = len(logs)
    success_count = sum(1 for l in logs if 'Success' in l['action'] or 'Verified' in l['action'])
    failed_count = sum(1 for l in logs if 'Failed' in l['action'])
    logout_count = sum(1 for l in logs if 'Logout' in l['action'])
    
    conn.close()
    
    return render_template('auth_log.html',
                           username=username,
                           logs=logs,
                           total=total,
                           success_count=success_count,
                           failed_count=failed_count,
                           logout_count=logout_count)

# ── EVENT LOG ──────────────────────────────────────────────
@app.route('/logs/events')
def event_log():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    conn = get_db()
    
    # Get ALL logs (system-wide)
    logs = conn.execute(
        'SELECT * FROM logs ORDER BY timestamp DESC LIMIT 200'
    ).fetchall()
    
    # Stats
    total = len(logs)
    normal_count = sum(1 for l in logs if l['threat_level'] == 'Normal')
    low_count = sum(1 for l in logs if l['threat_level'] == 'Low')
    high_count = sum(1 for l in logs if l['threat_level'] == 'High')
    
    # Unique users
    unique_users = len(set(l['username'] for l in logs if l['username']))
    
    conn.close()
    
    return render_template('event_log.html',
                           username=username,
                           logs=logs,
                           total=total,
                           normal_count=normal_count,
                           low_count=low_count,
                           high_count=high_count,
                           unique_users=unique_users)

# ═══════════════════════════════════════════════════════════
#  EXTERNAL API — For Attacker Simulator
# ═══════════════════════════════════════════════════════════

from flask import jsonify

@app.route('/api/ids/analyze', methods=['POST'])
def api_ids_analyze():
    """
    External API endpoint for the attacker simulator.
    Accepts network traffic features and returns ML analysis.
    Also logs everything as if it was a real incoming attack.
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract source info
        source_ip = data.get('source_ip', request.remote_addr)
        attack_name = data.get('attack_name', 'unknown')
        features = data.get('features', {})
        
        if not features:
            return jsonify({'error': 'No features provided'}), 400
        
        # Run ensemble prediction (RF + Autoencoder)
        result = ensemble_predict(features)
        
        # Get SHAP explanation
        try:
            explanation = explain_prediction(features,
                                              result['rf']['prediction'],
                                              top_n=5)
        except Exception as e:
            explanation = []
        
        # Log the "incoming attack" to database
        action = (f"EXTERNAL: {attack_name} from {source_ip} → "
                  f"{result['verdict']} "
                  f"(RF: {result['rf']['prediction']}, "
                  f"AE: {'Anomaly' if result['ae']['is_anomaly'] else 'Normal'})")
        
        conn = get_db()
        conn.execute(
            '''INSERT INTO logs (username, action, ip_address, threat_level)
               VALUES (?, ?, ?, ?)''',
            ('EXTERNAL', action, source_ip, result['verdict_level'])
        )
        conn.commit()
        conn.close()
        
        if result['verdict_level'] == 'High':
            logging.warning(f"EXTERNAL ATTACK DETECTED | {attack_name} | "
                            f"Source: {source_ip}")
        
        return jsonify({
            'verdict': result['verdict'],
            'verdict_level': result['verdict_level'],
            'agreement_score': result['agreement_score'],
            'rf': result['rf'],
            'ae': result['ae'],
            'explanation': explanation,
            'source_ip': source_ip,
            'attack_name': attack_name,
            'timestamp': str(datetime.now())
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/live-feed')
def api_live_feed():
    """
    Returns the latest 20 events for live feed polling.
    Includes both EXTERNAL and user actions.
    """
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = get_db()
    logs = conn.execute(
        '''SELECT id, username, action, ip_address, timestamp, threat_level
           FROM logs
           WHERE action LIKE 'IDS%' OR action LIKE 'EXTERNAL%'
           ORDER BY id DESC LIMIT 20'''
    ).fetchall()
    conn.close()
    
    return jsonify({
        'events': [{
            'id': row['id'],
            'username': row['username'],
            'action': row['action'],
            'ip_address': row['ip_address'],
            'timestamp': row['timestamp'],
            'threat_level': row['threat_level']
        } for row in logs]
    })

# ── Run ────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)