docker build -t agent-go . && docker create --name temp-container agent-go && docker cp temp-container:/myServiceAgent.exe ./myServiceAgent.exe && docker rm temp-container
