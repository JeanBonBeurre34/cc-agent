package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

var elog debug.Log

type Command struct {
	ID  string `json:"id"`
	Cmd string `json:"cmd"`
}

type CommandResult struct {
	ID     string `json:"id"`
	Result string `json:"result"`
}

type myService struct{}

var (
	mu               sync.Mutex
	isCommandRunning bool
)

func fetchCommand() (Command, error) {
	var cmd Command
	resp, err := http.Get("http://localhost:5000/command")
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

	resp, err := http.Post("http://localhost:5000/submit_result", "application/json", bytes.NewBuffer(jsonData))
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
		elog.Error(1, fmt.Sprintf("Error sending result for command ID %s: %s", cmd.ID, err))
	} else {
		elog.Info(1, fmt.Sprintf("Result for command ID %s sent successfully", cmd.ID))
	}
}

func (m *myService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	ticker := time.NewTicker(5 * time.Minute)
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	go func() {
		for range ticker.C {
			mu.Lock()
			if !isCommandRunning {
				isCommandRunning = true
				mu.Unlock()

				cmd, err := fetchCommand()
				if err != nil {
					elog.Error(1, fmt.Sprintf("Error fetching command: %s", err))
				} else if cmd.ID != "" {
					executeCommandAndSendResult(cmd)
				}

				mu.Lock()
				isCommandRunning = false
			}
			mu.Unlock()
		}
	}()

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				ticker.Stop()
				break loop
			default:
				elog.Error(1, fmt.Sprintf("Unexpected control request #%d", c.Cmd))
			}
		}
	}

	return false, 0
}

func runService(name string, isDebug bool) {
	var err error
	if isDebug {
		elog = debug.New(name)
	} else {
		elog, err = eventlog.Open(name)
		if err != nil {
			os.Exit(1)
		}
	}
	defer elog.Close()

	err = svc.Run(name, &myService{})
	if err != nil {
		elog.Error(1, fmt.Sprintf("Service failed: %v", err))
	}
}

func main() {
	isInteractive, err := svc.IsAnInteractiveSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to determine if we are running in an interactive session: %v", err)
		return
	}
	if !isInteractive {
		serviceName := "MyGoService"
		runService(serviceName, false)
		return
	}
	fmt.Fprintf(os.Stderr, "Running in debug mode\n")
	runService("MyGoServiceDebug", true)
}
