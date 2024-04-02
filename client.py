# client.py
import requests
import time

SERVER_URL = "http://localhost:5000"

def submit_command(cmd):
    response = requests.post(f"{SERVER_URL}/submit_command", json={"cmd": cmd})
    if response.status_code == 200:
        cmd_id = response.json()["id"]
        print(f"Command submitted successfully. ID: {cmd_id}")
        return cmd_id
    else:
        print("Failed to submit command.")
        return None

def get_result(cmd_id):
    response = requests.get(f"{SERVER_URL}/result/{cmd_id}")
    if response.status_code == 200:
        result = response.json()["result"]
        print(f"Result for command {cmd_id}: {result}")
    else:
        print(f"Failed to get result for command {cmd_id}.")

if __name__ == "__main__":
    cmd = "echo Hello, World!"  # Example command
    cmd_id = submit_command(cmd)
    if cmd_id:
        print("Waiting for the result...")
        time.sleep(2)  # Wait a bit before polling for the result
        get_result(cmd_id)
