import requests
import argparse

def submit_command(server_url, cmd):
    response = requests.post(f"{server_url}/submit_command", json={"cmd": cmd})
    if response.status_code == 200:
        cmd_id = response.json().get("id")
        print(f"Command submitted successfully. ID: {cmd_id}")
        return cmd_id
    else:
        print("Failed to submit command.")
        return None

def get_result(server_url, cmd_id):
    response = requests.get(f"{server_url}/result/{cmd_id}")
    if response.status_code == 200:
        result = response.json().get("result")
        print(f"Result for command {cmd_id}: {result}")
    else:
        print(f"Failed to get result for command {cmd_id}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Send commands to server and fetch results.')
    parser.add_argument('command', type=str, help='Command to execute remotely.')
    parser.add_argument('--server', type=str, default='http://localhost:5000', help='Server URL (default: http://localhost:5000)')

    args = parser.parse_args()

    cmd_id = submit_command(args.server, args.command)
    if cmd_id:
        print("Waiting for the result...")
        get_result(args.server, cmd_id)
