# server.py
from flask import Flask, request, jsonify
from queue import Queue

app = Flask(__name__)
commands_queue = Queue()
results = {}

@app.route('/submit_command', methods=['POST'])
def submit_command():
    if request.is_json:
        data = request.get_json()
        cmd_id = str(len(results) + 1)  # Simple ID generation
        commands_queue.put((cmd_id, data['cmd']))
        results[cmd_id] = "Pending"
        return jsonify({"id": cmd_id}), 200
    return jsonify({"error": "Request must be JSON"}), 400

@app.route('/command')
def get_command():
    if not commands_queue.empty():
        cmd_id, cmd = commands_queue.get()
        return jsonify({"id": cmd_id, "cmd": cmd}), 200
    return jsonify({"error": "No commands in queue"}), 404

@app.route('/submit_result', methods=['POST'])
def submit_result():
    if request.is_json:
        data = request.get_json()
        cmd_id = data['id']
        if cmd_id in results:
            results[cmd_id] = data['result']
            return jsonify({"message": "Result updated successfully"}), 200
        return jsonify({"error": "Invalid command ID"}), 404
    return jsonify({"error": "Request must be JSON"}), 400

@app.route('/result/<cmd_id>', methods=['GET'])
def get_result(cmd_id):
    if cmd_id in results:
        return jsonify({"id": cmd_id, "result": results[cmd_id]}), 200
    return jsonify({"error": "Invalid command ID"}), 404

if __name__ == '__main__':
    app.run(debug=True)
