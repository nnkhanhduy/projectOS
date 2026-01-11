
import os
import socket
import json
import subprocess
import logging
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Configuration
SOCKET_PATH = "/var/run/firewall.sock"
# Try to locate the config file relative to this script or use default build path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE_PATH = os.path.join(BASE_DIR, "../firewall/build/firewall_configs.json")
DNS_CONFIG_PATH = os.path.join(BASE_DIR, "../firewall/build/ioc_dns.json")

def send_command(command_data):
    """Send JSON command to the Unix socket."""
    if not os.path.exists(SOCKET_PATH):
        return {"status": "error", "msg": "Firewall daemon is not running (socket not found)"}

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(SOCKET_PATH)
        client.sendall(json.dumps(command_data).encode('utf-8'))
        
        # Read response
        response = client.recv(4096)
        if not response:
            return {"status": "error", "msg": "No response from daemon"}
            
        return json.loads(response.decode('utf-8'))
    except Exception as e:
        return {"status": "error", "msg": str(e)}
    finally:
        client.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/rules', methods=['GET'])
def get_rules():
    """Read current firewall rules from JSON file."""
    if not os.path.exists(CONFIG_FILE_PATH):
        return jsonify([])
    
    try:
        with open(CONFIG_FILE_PATH, 'r') as f:
            data = json.load(f)
            return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/rules', methods=['POST'])
def add_rule():
    """Add a new blocking rule."""
    data = request.json
    # payload for daemon
    payload = {
        "cmd": "add_rule",
        "rule": {
            "src_ip": data.get("src_ip", "any"),
            "dst_ip": data.get("dst_ip", "any"),
            "src_port": data.get("src_port", "any"),
            "dst_port": data.get("dst_port", "any"),
            "protocol": data.get("protocol", "any"),
            "action": data.get("action", "DENY")
        }
    }
    
    resp = send_command(payload)
    return jsonify(resp)

@app.route('/api/rules', methods=['DELETE'])
def remove_rule():
    """Remove a blocking rule."""
    data = request.json
    payload = {
        "cmd": "remove_rule",
        "rule": {
            "src_ip": data.get("src_ip", "any"),
            "dst_ip": data.get("dst_ip", "any"),
            "src_port": data.get("src_port", "any"),
            "dst_port": data.get("dst_port", "any"),
            "protocol": data.get("protocol", "any")
        }
    }
    resp = send_command(payload)
    return jsonify(resp)

@app.route('/api/dns/block', methods=['POST'])
def block_domain():
    data = request.json
    domain = data.get("domain")
    if not domain:
        return jsonify({"status": "error", "msg": "Missing domain"}), 400
        
    payload = {
        "cmd": "block_domain",
        "domain": domain
    }
    resp = send_command(payload)
    return jsonify(resp)

@app.route('/api/limit', methods=['POST'])
def set_rate_limit():
    data = request.json
    ip = data.get("ip")
    rate = data.get("rate")
    capacity = data.get("capacity")
    
    if not ip or not rate or not capacity:
         return jsonify({"status": "error", "msg": "Missing parameters"}), 400

    payload = {
        "cmd": "set_rate_limit",
        "ip": ip,
        "rate": float(rate),
        "capacity": float(capacity)
    }
    resp = send_command(payload)
    return jsonify(resp)

@app.route('/api/dns', methods=['GET'])
def get_dns_rules():
    """Read current DNS blocklist."""
    if not os.path.exists(DNS_CONFIG_PATH):
        return jsonify([])
    try:
        with open(DNS_CONFIG_PATH, 'r') as f:
            data = json.load(f)
            return jsonify(data.get("blocked_domains", []))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/test/exec', methods=['POST'])
def test_network():
    data = request.json
    tool = data.get("tool")
    target = data.get("target")
    
    if not tool or not target:
        return jsonify({"status": "error", "msg": "Missing parameters"}), 400

    cmd = []
    if tool == "ping":
        # Ping 4 times, 1s timeout
        cmd = ["ping", "-c", "4", "-W", "1", target]
    elif tool == "dns":
        # Use dig with explicit DNS server 8.8.8.8
        cmd = ["dig", "@8.8.8.8", "+short", target]
    elif tool == "http":
        # Curl headers only
        cmd = ["curl", "-I", "--connect-timeout", "3", target]
    else:
        return jsonify({"status": "error", "msg": "Invalid tool"}), 400

    try:
        # Run command
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
        return jsonify({"status": "ok", "output": result.stdout})
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
