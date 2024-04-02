# cc-agent

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
