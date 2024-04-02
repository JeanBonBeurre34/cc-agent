package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "sync"
    "time"
)

type Command struct {
    ID  string `json:"id"`
    Cmd string `json:"cmd"`
}

type CommandResult struct {
    ID     string `json:"id"`
    Result string `json:"result"`
}

var (
    mu               sync.Mutex
    isCommandRunning bool
)

func fetchCommand() (Command, error) {
    var cmd Command
    resp, err := http.Get("http://192.168.56.101:5000/command")
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

func sendResult(result CommandResult) error {
    jsonData, err := json.Marshal(result)
    if err != nil {
        return err
    }

    resp, err := http.Post("http://192.168.56.101:5000/submit_result", "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    return nil
}

func executeCommandAndSendResult(cmd Command) {
    resultText := fmt.Sprintf("Executed command: %s", cmd.Cmd)

    result := CommandResult{
        ID:     cmd.ID,
        Result: resultText,
    }

    err := sendResult(result)
    if err != nil {
        fmt.Printf("Error sending result for command ID %s: %s\n", cmd.ID, err)
    } else {
        fmt.Printf("Result for command ID %s sent successfully\n", cmd.ID)
    }
}

func main() {
    fmt.Println("Application started. Press CTRL+C to exit.")
    ticker := time.NewTicker(1 * time.Minute)
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

    // Prevent the application from exiting immediately
    select {}
}
