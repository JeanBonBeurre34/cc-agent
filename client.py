import argparse
import requests
import os

# Define the base URL of your command and control server
SERVER_URL = "http://192.168.56.101:5000"

# Get token from environment
AGENT_TOKEN = os.getenv("AGENT_TOKEN")
if not AGENT_TOKEN:
    raise RuntimeError("AGENT_TOKEN not set in environment")

HEADERS = {
    "Authorization": f"Bearer {AGENT_TOKEN}",
    "Content-Type": "application/json"
}

def submit_command(server_url, cmd):
    response = requests.post(f"{server_url}/submit_command", json={"cmd": cmd}, headers=HEADERS)
    if response.status_code == 200:
        cmd_id = response.json().get("id")
        print(f"✅ Command submitted successfully. ID: {cmd_id}")
        return cmd_id
    else:
        print(f"❌ Failed to submit command: {response.status_code} - {response.text}")
        return None

def get_result(server_url, cmd_id):
    response = requests.get(f"{server_url}/result/{cmd_id}", headers=HEADERS)
    if response.status_code == 200:
        result = response.json().get("result")
        print(f"💡 Result for command {cmd_id}: {result}")
    else:
        print(f"❌ Failed to get result for command {cmd_id}: {response.status_code} - {response.text}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Interact with the remote command server.")
    parser.add_argument("--command", type=str, help="Command to execute on the remote agent.")
    parser.add_argument("--get_result", type=str, help="Command ID to retrieve the result for.")
    parser.add_argument("--server", type=str, default=SERVER_URL, help="Command server URL.")

    args = parser.parse_args()

    if args.command:
        cmd_id = submit_command(args.server, args.command)
        if cmd_id:
            print(f"Command submitted successfully. ID: {cmd_id}")
    elif args.get_result:
        get_result(args.server, args.get_result)
    else:
        print("No action specified. Use --command to submit a new command or --get_result to fetch command results.")

