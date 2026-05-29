package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	Port        = ":8080"
	CmdStart    = "START"
	CmdStop     = "STOP"
	CmdGenerate = "GENERATE"
)

type ZKPLiveService struct {
	listener  net.Listener
	mu        sync.Mutex
	isRunning bool
	stopChan  chan struct{}
}

var Instance = &ZKPLiveService{
	stopChan: make(chan struct{}),
}

// StartService handles the service lifecycle, setups keys safely, and manages client connections.
func (s *ZKPLiveService) StartService() {
	s.mu.Lock()
	if s.isRunning {
		fmt.Println("[CORE]     The service is already running online.")
		s.mu.Unlock()
		return
	}
	s.isRunning = true
	s.stopChan = make(chan struct{})
	s.mu.Unlock()

	var err error
	s.listener, err = net.Listen("tcp", Port)
	if err != nil {
		fmt.Printf("[CORE]      Unable to open service port: %v\n", err)
		return
	}
	fmt.Printf("[CORE]      The ZKP Online service has STARTED on port %s\n", Port)

	// FIX LOGIC: Smart asset initialization rule for Cosmos SDK production
	// Only run setup if the system keys are missing from the permanent config folder
	pkPath := filepath.Join(ConfigDir, "proving.key")
	vkPath := filepath.Join(ConfigDir, "verifying.key")

	if _, errPk := os.Stat(pkPath); os.IsNotExist(errPk) {
		fmt.Println("[CORE]     System keys not found. Initializing permanent arithmetic circuit setup...")
		if err := SetupSystem(); err != nil {
			fmt.Printf("[CORE]      Automatic Setup failed: %v\n", err)
		}
	} else {
		// Secure bypass: reuse existing verified assets to stay compatible with the blockchain parameters
		fmt.Println("[CORE]     Permanent keys detected inside config folder. Reusing existing system assets.")
		_ = vkPath // Explicit bypass for unused var check if needed
	}

	// Start accepting client connections
	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.stopChan:
					return
				default:
					continue
				}
			}
			go s.handleClient(conn)
		}
	}()
}

// StopService shuts down the online gateway and clears session caches cleanly
func (s *ZKPLiveService) StopService() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isRunning {
		fmt.Println("[ERROR]     The service is currently closed; there's no need to stop it.")
		return
	}

	s.isRunning = false
	close(s.stopChan)
	if s.listener != nil {
		s.listener.Close()
	}
	fmt.Println("[CORE]     The ZKP Online service has ENDED safely.")

	// Triggers the smart session data wipeout (protects the keys, removes transaction session data)
	ClearAllSessionData()
}

// Handle incoming client connections and parse streaming requests
func (s *ZKPLiveService) handleClient(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	message, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	message = strings.TrimSpace(message)
	parts := strings.Split(message, "|")
	command := parts[0]

	switch command {
	case CmdStart:
		s.StartService()
		conn.Write([]byte("[SUCCESS]    Service Started\n"))

	case CmdGenerate:
		if len(parts) < 3 {
			conn.Write([]byte("[ERROR]      Insufficient parameters for X and Y\n"))
			return
		}
		// Parse X and Y from the stream
		x, _ := strconv.ParseInt(parts[1], 10, 64)
		y, _ := strconv.ParseInt(parts[2], 10, 64)

		fmt.Printf("[CORE]      Service receives task: Generate Proof for X=%d, Y=%d\n", x, y)

		err := GenerateProof(x, y)
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("[ERROR]      Failed to generate proof: %v\n", err)))
		} else {
			// Returns success response. This will be caught by bat.RelayGenerateRequest using strings.Contains
			conn.Write([]byte("[SUCCESS]    Proof Generated and Cached\n"))
		}

	case CmdStop:
		conn.Write([]byte("[SUCCESS]    Service stopping...\n"))
		go func() {
			time.Sleep(500 * time.Millisecond)
			s.StopService()
		}()

	default:
		conn.Write([]byte("[ERROR]      Invalid command\n"))
	}
}
