package main

import (
	"bufio"
	"fmt"
	"gazk/bat"
	"gazk/core"
	"net"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		Guide()
		return
	}

	cmd := strings.ToUpper(os.Args[1])

	switch cmd {
	case "SERVER":
		//
		core.Instance.StartService()
		//
		select {}

	case "START":
		//
		phảnHồi := sendCmd("START")
		fmt.Printf("[SYS]		Result: %s\n", phảnHồi)

	case "GENERATE":
		if len(os.Args) < 4 {
			fmt.Println("[WARNING]		Please enter all parameters. For example: go run main.go generate 3 35")
			return
		}
		var x, y int64
		fmt.Sscanf(os.Args[2], "%d", &x)
		fmt.Sscanf(os.Args[3], "%d", &y)

		res := bat.RequestPayload{SecretX: x, PublicY: y}
		result := bat.RelayGenerateRequest(res)

		//
		if result.Status == "SUCCESS" {
			jsonString, err := result.ExportToJSON()
			if err != nil {
				fmt.Printf("[SYS]		Error exporting JSON: %v\n", err)
				return
			}

			//
			fname := "api.json"
			err = bat.SaveJSONToFile(fname, jsonString)
			if err != nil {
				fmt.Printf("[SYS]		Error saving file: %v\n", err)
				return
			}

			fmt.Println("\n----------------JSON FILE")
			fmt.Println(jsonString)
		} else {
			fmt.Printf("[SYS]		Failure at the bridge: %s\n", result.Message)
		}

	case "STOP":
		//
		phảnHồi := sendCmd("STOP")
		fmt.Printf("[SYS]		Result: %s\n", phảnHồi)

	default:
		Guide()
	}
}

func sendCmd(pack string) string {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		return fmt.Sprintf("[ERROR] 	Failed to connect to ZKP Service. It might not be running with the 'SERVER' command: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, pack+"\n")
	res, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Sprintf("[ERROR] 	Error reading feedback: %v", err)
	}
	return strings.TrimSpace(res)
}

func Guide() {
	fmt.Println("----------------GUIDE")
	fmt.Println("1. Start:		go run main.go server")
	fmt.Println("2. Response:	go run main.go generate [X] [Y]")
	fmt.Println("3. Stop:		go run main.go stop")
	fmt.Println("==================================================")
}
