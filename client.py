import argparse
import requests
import os
import urllib3

# --- Default server values ---
DEFAULT_HOST = "192.168.56.101"
DEFAULT_PORT = 5000

# --- Get token from environment ---
AGENT_TOKEN = os.getenv("AGENT_TOKEN")
if not AGENT_TOKEN:
    raise RuntimeError("AGENT_TOKEN not set in environment")

HEADERS = {
    "Authorization": f"Bearer {AGENT_TOKEN}",
    "Content-Type": "application/json"
}

# --- Core functions ---

def build_base_url(use_https, host, port):
    """Build server URL depending on HTTPS toggle."""
    protocol = "https" if use_https else "http"
    return f"{protocol}://{host}:{port}"

def submit_command(server_url, cmd, verify_ssl):
    response = requests.post(
        f"{server_url}/submit_command",
        json={"cmd": cmd},
        headers=HEADERS,
        verify=verify_ssl
    )
    if response.status_code == 200:
        cmd_id = response.json().get("id")
        print(f"✅ Command submitted successfully. ID: {cmd_id}")
        return cmd_id
    else:
        print(f"❌ Failed to submit command: {response.status_code} - {response.text}")
        return None

def get_result(server_url, cmd_id, verify_ssl):
    response = requests.get(
        f"{server_url}/result/{cmd_id}",
        headers=HEADERS,
        verify=verify_ssl
    )
    if response.status_code == 200:
        result = response.json().get("result")
        print(f"💡 Result for command {cmd_id}: {result}")
    else:
        print(f"❌ Failed to get result for command {cmd_id}: {response.status_code} - {response.text}")

# --- Entry point ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Interact with the remote command server.")
    parser.add_argument("--command", type=str, help="Command to execute on the remote agent.")
    parser.add_argument("--get_result", type=str, help="Command ID to retrieve the result for.")
    parser.add_argument("--host", type=str, default=DEFAULT_HOST, help="Server hostname or IP.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port number.")
    parser.add_argument("--https", action="store_true", help="Use HTTPS instead of HTTP (self-signed allowed).")

    args = parser.parse_args()

    # Configure protocol and SSL verification
    base_url = build_base_url(args.https, args.host, args.port)
    if args.https:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        verify_ssl = False  # accept self-signed certs for testing
        print(f"[+] Using HTTPS (self-signed OK): {base_url}")
    else:
        verify_ssl = True
        print(f"[+] Using HTTP: {base_url}")

    # Run requested action
    if args.command:
        cmd_id = submit_command(base_url, args.command, verify_ssl)
        if cmd_id:
            print(f"Command submitted successfully. ID: {cmd_id}")
    elif args.get_result:
        get_result(base_url, args.get_result, verify_ssl)
    else:
        print("No action specified. Use --command to submit or --get_result to fetch results.")

                              
