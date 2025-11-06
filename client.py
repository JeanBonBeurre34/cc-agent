!/usr/bin/env python3
import argparse
import requests
import os
import urllib3

# --- Default values ---
DEFAULT_HOST = "192.168.56.101"
DEFAULT_PORT = 5000

# --- Authentication ---
AGENT_TOKEN = os.getenv("AGENT_TOKEN")
if not AGENT_TOKEN:
    raise RuntimeError("AGENT_TOKEN not set in environment")

HEADERS_BASE = {
    "Authorization": f"Bearer {AGENT_TOKEN}",
    "Content-Type": "application/json"
}

# --- Utilities ---
def build_base_url(use_https, host, port):
    """Return full base URL based on flags."""
    proto = "https" if use_https else "http"
    return f"{proto}://{host}:{port}"


# --- Command submission ---
def submit_command(server_url, cmd, agent_id=None, verify_ssl=True):
    """Submit a command, optionally for a specific agent."""
    data = {"cmd": cmd}
    if agent_id:
        data["target_agent"] = agent_id
    resp = requests.post(f"{server_url}/submit_command", json=data, headers=HEADERS_BASE, verify=verify_ssl)
    if resp.status_code == 200:
        cid = resp.json().get("id")
        print(f"✅ Command #{cid} submitted to {agent_id or 'ALL'}")
        return cid
    else:
        print(f"❌ Failed: {resp.status_code} - {resp.text}")
        return None


# --- Get results for one or all agents ---
def get_results(server_url, agent_id=None, verify_ssl=True):
    """Retrieve results for all or specific agent."""
    params = {}
    if agent_id:
        params["agent_id"] = agent_id
    resp = requests.get(f"{server_url}/get_results", headers=HEADERS_BASE, params=params, verify=verify_ssl)
    if resp.status_code == 200:
        results = resp.json()
        if not results:
            print("No results available.")
            return
        print(f"✅ {len(results)} result(s):\n")
        for r in results:
            print(f"• Command {r['cmd_id']} | Agent: {r['agent_id']}")
            if r.get("fileName"):
                print(f"  File: {r['fileName']}")
            print(f"  Output:\n{r['output']}\n---\n")
    else:
        print(f"❌ Error fetching results: {resp.status_code} - {resp.text}")


# --- List connected agents ---
def list_agents(server_url, verify_ssl=True):
    """List all active agents tracked by the server."""
    resp = requests.get(f"{server_url}/list_agents", headers=HEADERS_BASE, verify=verify_ssl)
    if resp.status_code == 200:
        agents = resp.json()
        if not agents:
            print("No active agents connected.")
            return
        print(f"✅ {len(agents)} agent(s) connected:\n")
        for a in agents:
            print(f"• Agent ID: {a['agent_id']}")
            print(f"  IP: {a['ip']}")
            print(f"  Last Seen: {a['last_seen']}\n")
    else:
        print(f"❌ Failed to list agents: {resp.status_code} - {resp.text}")


# --- Entry point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Remote command client supporting HTTPS and per-agent targeting.")
    parser.add_argument("--submit","--command", type=str, help="Submit a command to a specific or all agents")
    parser.add_argument("--get-results", action="store_true", help="Fetch command results (optionally per agent)")
    parser.add_argument("--list-agents", action="store_true", help="List all connected agents")
    parser.add_argument("--agent-id", type=str, help="Target a specific agent ID")
    parser.add_argument("--host", type=str, default=DEFAULT_HOST, help="Server hostname or IP")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port number")
    parser.add_argument("--https", action="store_true", help="Use HTTPS (self-signed cert accepted)")

    args = parser.parse_args()

    # --- Configure base URL and SSL ---
    base_url = build_base_url(args.https, args.host, args.port)
    if args.https:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        verify_ssl = False  # Accept self-signed certs
        print(f"[+] Using HTTPS (self-signed OK): {base_url}")
    else:
        verify_ssl = True
        print(f"[+] Using HTTP: {base_url}")

    # --- Execute requested action ---
    if args.submit:
        submit_command(base_url, args.submit, args.agent_id, verify_ssl)
    elif args.get_results:
        get_results(base_url, args.agent_id, verify_ssl)
    elif args.list_agents:
        list_agents(base_url, verify_ssl)
    else:
        parser.print_help()
