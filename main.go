package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/zhenjb/gazk/bat"
	"github.com/zhenjb/gazk/prover"
	"github.com/zhenjb/gazk/server"
)

const defaultHTTPAddr = ":8090"

func main() {
	if len(os.Args) < 2 {
		Guide()
		return
	}

	cmd := strings.ToUpper(os.Args[1])

	switch cmd {
	case "SERVER":
		addr := getenv("GAZK_ADDR", defaultHTTPAddr)
		httpServer := server.NewHTTPServer(prover.NewService())

		fmt.Printf("[GAZK] HTTP prover service listening on http://localhost%s\n", addr)

		if err := http.ListenAndServe(addr, httpServer.Routes()); err != nil {
			fmt.Printf("[GAZK] server error: %v\n", err)
			os.Exit(1)
		}

	case "START":
		response := sendCmd("START")
		fmt.Printf("[SYS] Result: %s\n", response)

	case "GENERATE":
		if len(os.Args) < 4 {
			fmt.Println("[WARNING] Please enter all parameters. For example: go run main.go generate 3 35")
			return
		}

		var x, y int64
		fmt.Sscanf(os.Args[2], "%d", &x)
		fmt.Sscanf(os.Args[3], "%d", &y)

		res := bat.RequestPayload{SecretX: x, PublicY: y}
		result := bat.RelayGenerateRequest(res)

		if result.Status == "SUCCESS" {
			jsonString, err := result.ExportToJSON()
			if err != nil {
				fmt.Printf("[SYS] Error exporting JSON: %v\n", err)
				return
			}

			fname := "api.json"
			err = bat.SaveJSONToFile(fname, jsonString)
			if err != nil {
				fmt.Printf("[SYS] Error saving file: %v\n", err)
				return
			}

			fmt.Println("\n----------------JSON FILE")
			fmt.Println(jsonString)
		} else {
			fmt.Printf("[SYS] Failure at the bridge: %s\n", result.Message)
		}

	case "STOP":
		response := sendCmd("STOP")
		fmt.Printf("[SYS] Result: %s\n", response)

	default:
		Guide()
	}
}

func sendCmd(pack string) string {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to connect to legacy ZKP service: %v", err)
	}
	defer conn.Close()

	fmt.Fprintln(conn, pack)

	res, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Sprintf("[ERROR] Error reading feedback: %v", err)
	}

	return strings.TrimSpace(res)
}

func Guide() {
	fmt.Println("----------------GUIDE")
	fmt.Println("1. HTTP server:      go run main.go server")
	fmt.Println("2. Health:           curl http://localhost:8090/health")
	fmt.Println("3. Prove:            POST http://localhost:8090/prove")
	fmt.Println("4. Verify:           POST http://localhost:8090/verify")
	fmt.Println("5. Legacy generate:  go run main.go generate [X] [Y]")
	fmt.Println("==================================================")
}

func getenv(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}
