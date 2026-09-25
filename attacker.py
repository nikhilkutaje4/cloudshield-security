"""
CloudShield RED TEAM — Attack Simulator
────────────────────────────────────────
Standalone attacker application that fires realistic attacks
at the CloudShield defender running on localhost:5000.

Run separately: python attacker.py
Access at: http://localhost:5001
"""

from flask import Flask, render_template, request, jsonify
import requests
import random
import json
from datetime import datetime

app = Flask(__name__)

# Target CloudShield endpoint
CLOUDSHIELD_URL = 'https://cloudshield-security.onrender.com/api/ids/analyze' 

# ── Attack Payload Library ──────────────────────────────────
ATTACK_PAYLOADS = {
    'dos_neptune': {
        'name': 'DoS · Neptune SYN Flood',
        'description': 'Classic SYN flood — overwhelms target with half-open connections',
        'severity': 'HIGH',
        'features': {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'private',
            'flag': 'S0', 'src_bytes': 0, 'dst_bytes': 0,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0,
            'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0,
            'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 123, 'srv_count': 6, 'serror_rate': 1.0,
            'srv_serror_rate': 1.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
            'same_srv_rate': 0.05, 'diff_srv_rate': 0.07,
            'srv_diff_host_rate': 0.0, 'dst_host_count': 255,
            'dst_host_srv_count': 26, 'dst_host_same_srv_rate': 0.10,
            'dst_host_diff_srv_rate': 0.05, 'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 1.0,
            'dst_host_srv_serror_rate': 1.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }
    },
    'probe_portscan': {
        'name': 'Probe · Port Scan',
        'description': 'Reconnaissance — scanning for open ports',
        'severity': 'MEDIUM',
        'features': {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'private',
            'flag': 'REJ', 'src_bytes': 0, 'dst_bytes': 0,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0,
            'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0,
            'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 229, 'srv_count': 10, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 1.0, 'srv_rerror_rate': 1.0,
            'same_srv_rate': 0.04, 'diff_srv_rate': 0.06,
            'srv_diff_host_rate': 0.0, 'dst_host_count': 255,
            'dst_host_srv_count': 10, 'dst_host_same_srv_rate': 0.04,
            'dst_host_diff_srv_rate': 0.06, 'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 1.0,
            'dst_host_srv_rerror_rate': 1.0
        }
    },
    'r2l_bruteforce': {
        'name': 'R2L · FTP Brute Force',
        'description': 'Password guessing attack against FTP service',
        'severity': 'HIGH',
        'features': {
            'duration': 30, 'protocol_type': 'tcp', 'service': 'ftp',
            'flag': 'SF', 'src_bytes': 200, 'dst_bytes': 300,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 5,
            'num_failed_logins': 5, 'logged_in': 0, 'num_compromised': 0,
            'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 1,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
            'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0, 'dst_host_count': 10,
            'dst_host_srv_count': 10, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.10,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }
    },
    'u2r_rootkit': {
        'name': 'U2R · Rootkit Installation',
        'description': 'Privilege escalation — attempt to gain root access',
        'severity': 'CRITICAL',
        'features': {
            'duration': 200, 'protocol_type': 'tcp', 'service': 'telnet',
            'flag': 'SF', 'src_bytes': 500, 'dst_bytes': 3000,
            'land': 0, 'wrong_fragment': 0, 'urgent': 3, 'hot': 15,
            'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 5,
            'root_shell': 1, 'su_attempted': 2, 'num_root': 10,
            'num_file_creations': 5, 'num_shells': 2, 'num_access_files': 3,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
            'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0, 'dst_host_count': 1,
            'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }
    },
    'normal_http': {
        'name': 'Normal · HTTP Request',
        'description': 'Legitimate web traffic (control test)',
        'severity': 'NONE',
        'features': {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'http',
            'flag': 'SF', 'src_bytes': 232, 'dst_bytes': 8153,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0,
            'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0,
            'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 5, 'srv_count': 5, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
            'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0, 'dst_host_count': 30,
            'dst_host_srv_count': 255, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.03,
            'dst_host_srv_diff_host_rate': 0.04, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }
    }
}

# ── Fake attacker IPs (for realism) ─────────────────────────
FAKE_IPS = [
    '192.168.1.42', '10.0.0.99', '172.16.5.13',
    '203.0.113.55', '198.51.100.7', '185.220.101.42',
    '45.33.32.156', '91.219.236.99', '89.248.167.131',
    '176.9.75.42'
]

# ── Routes ──────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('attacker.html', 
                           payloads=ATTACK_PAYLOADS,
                           target=CLOUDSHIELD_URL)

@app.route('/fire/<attack_type>', methods=['POST'])
def fire_attack(attack_type):
    """Fire a single attack at CloudShield"""
    if attack_type not in ATTACK_PAYLOADS:
        return jsonify({'error': 'Unknown attack'}), 400
    
    payload = ATTACK_PAYLOADS[attack_type]
    source_ip = request.json.get('source_ip') or random.choice(FAKE_IPS)
    
    try:
        response = requests.post(
            CLOUDSHIELD_URL,
            json={
                'attack_name': payload['name'],
                'source_ip': source_ip,
                'features': payload['features']
            },
            timeout=5
        )
        
        return jsonify({
            'success': True,
            'attack': payload['name'],
            'source_ip': source_ip,
            'target_response': response.json(),
            'status_code': response.status_code
        })
    except requests.exceptions.ConnectionError:
        return jsonify({
            'success': False,
            'error': 'Target unreachable — is CloudShield running on port 5000?'
        }), 503
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/fire-custom', methods=['POST'])
def fire_custom():
    """Fire a custom-built attack"""
    data = request.get_json()
    features = data.get('features', {})
    attack_name = data.get('attack_name', 'Custom Attack')
    source_ip = data.get('source_ip') or random.choice(FAKE_IPS)
    
    try:
        response = requests.post(
            CLOUDSHIELD_URL,
            json={
                'attack_name': attack_name,
                'source_ip': source_ip,
                'features': features
            },
            timeout=5
        )
        return jsonify({
            'success': True,
            'attack': attack_name,
            'source_ip': source_ip,
            'target_response': response.json()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/rapid-fire', methods=['POST'])
def rapid_fire():
    """Fire multiple attacks in sequence"""
    data = request.get_json()
    attack_types = data.get('attacks', [])
    results = []
    
    for attack_type in attack_types:
        if attack_type in ATTACK_PAYLOADS:
            payload = ATTACK_PAYLOADS[attack_type]
            source_ip = random.choice(FAKE_IPS)
            try:
                response = requests.post(
                    CLOUDSHIELD_URL,
                    json={
                        'attack_name': payload['name'],
                        'source_ip': source_ip,
                        'features': payload['features']
                    },
                    timeout=5
                )
                results.append({
                    'attack': payload['name'],
                    'source_ip': source_ip,
                    'verdict': response.json().get('verdict', 'unknown'),
                    'success': True
                })
            except Exception as e:
                results.append({
                    'attack': payload['name'],
                    'success': False,
                    'error': str(e)
                })
    
    return jsonify({'results': results, 'total': len(results)})

# ── Run ────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 60)
    print("  🔴 CLOUDSHIELD RED TEAM — Attack Simulator")
    print("=" * 60)
    print(f"  Target: {CLOUDSHIELD_URL}")
    print(f"  Console: http://127.0.0.1:5001")
    print("=" * 60)
    app.run(debug=True, port=5001)