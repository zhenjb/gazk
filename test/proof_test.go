//go:build legacy_online
// +build legacy_online

package test

import (
	"bufio"
	"fmt"
	"github.com/zhenjb/gazk/core"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCircuitLogic(t *testing.T) {
	// 1. Setup the system first to generate permanent keys and circuit configurations.
	err := core.SetupSystem()
	if err != nil {
		t.Fatalf("[ERROR]      System infrastructure setup failed: %v", err)
	}

	// 2. Test with correct mathematical assignment values (3^3 + 3 + 5 = 35)
	t.Run("Data_Accept", func(t *testing.T) {
		err = core.GenerateProof(3, 35)
		if err != nil {
			t.Fatalf("[ERROR]      The data is correct, but proof generation faulted: %v", err)
		}

		isValid, err := core.VerifyProof()
		if err != nil {
			t.Fatalf("[ERROR]      Verifier execution returned an unexpected system error: %v", err)
		}
		if !isValid {
			t.Fatalf("[ERROR]      The proof is valid, but the Verifier mathematically rejected it!")
		}
	})

	// 3. FIX LOGIC: Adapt to Gnark's strict Prover constraint checking
	t.Run("Data_Failed", func(t *testing.T) {
		err = core.GenerateProof(3, 999)

		// If Gnark catches the invalid constraints during Proving stage, it's a SUCCESSFUL rejection.
		if err != nil {
			t.Logf("[SUCCESS]    Engine successfully caught invalid assignment during Proving: %v", err)
			return // Test passes!
		}

		// Fallback check: If proof was generated anyway, the Verifier MUST reject it.
		isValid, err := core.VerifyProof()
		if err != nil {
			t.Fatalf("[ERROR]      Verifier threw an unexpected error: %v", err)
		}
		if isValid {
			t.Fatalf("[ERROR]      SECURITY CRITICAL: The system verified an invalid proof assertion (X=3, Y=999)!")
		}
	})
}

func TestOnlineServiceFlow(t *testing.T) {
	// Clean session space before mounting the service pipeline
	core.ClearAllSessionData()

	// Ensure port 8080 is clear before spinning up a new service instance
	// This avoids "bind: Only one usage of each socket address" error
	if conn, err := net.Dial("tcp", "localhost:8080"); err == nil {
		conn.Close()
		t.Log("[WARNING]    Port 8080 is already occupied by a running server instance. Testing against the active instance.")
	} else {
		// Start a fresh test service instance if the port is free
		go core.Instance.StartService()
		time.Sleep(600 * time.Millisecond)
	}

	// Helper function for sending explicit protocol commands across the streaming boundary
	sendCmd := func(cmd string) string {
		conn, err := net.Dial("tcp", "localhost:8080")
		if err != nil {
			t.Fatalf("[ERROR]      Cannot establish connection to ZKP network daemon: %v", err)
		}
		defer conn.Close()

		fmt.Fprintf(conn, "%s\n", cmd)
		resp, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatalf("[ERROR]      Failed reading network response buffer stream: %v", err)
		}
		return resp
	}

	// Test the active TCP Socket handling valid parameters (5^3 + 5 + 5 = 135)
	t.Run("Service_Generate_Valid", func(t *testing.T) {
		resp := sendCmd("GENERATE|5|135")
		if !strings.Contains(resp, "SUCCESS") {
			t.Fatalf("[WARNING]    The online gateway rejected a legitimate transaction request: %s", resp)
		}
	})

	// Test the active TCP Socket rejecting mathematically broken balances
	t.Run("Service_Generate_Invalid", func(t *testing.T) {
		resp := sendCmd("GENERATE|5|999")
		// The service now handles invalid constraints and returns an [ERROR] packet
		if !strings.Contains(resp, "ERROR") {
			t.Fatalf("[WARNING]    The service approved or failed to report the wrong data: %s", resp)
		}
	})

	// Gracefully issue an administrative remote disconnection command
	t.Run("Service_Stop_Remote", func(t *testing.T) {
		resp := sendCmd("STOP")
		if !strings.Contains(resp, "SUCCESS") {
			t.Fatalf("[WARNING]    Administrative node failed to command remote lifecycle termination: %s", resp)
		}
		// Allow small buffer window for local context thread to flush disk caches and close ports safely
		time.Sleep(600 * time.Millisecond)
	})
}

// TestMain coordinates package execution wrappers and handles post-mortem workspace garbage collection.
func TestMain(m *testing.M) {
	// Run testing pipelines
	exitCode := m.Run()

	// Post-execution routine: purge all transaction histories, leave verification keys intact
	fmt.Println("\n[TEST]       Scanning session space and running post-mortem data purge...")
	core.ClearAllSessionData()

	os.Exit(exitCode)
}
