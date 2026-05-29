package bat

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	ServiceAddr = "localhost:8080"
	ConfigDir   = "config"
	CacheDir    = "cache"
)

type RequestPayload struct {
	SecretX int64 `json:"secret_x"`
	PublicY int64 `json:"public_y"`
}

type ResponsePayload struct {
	Status        string `json:"status"`
	Message       string `json:"message"`
	Proof         []byte `json:"proof"`
	PublicKey     []byte `json:"verification_key"`
	PublicWitness []byte `json:"witness"`
}

// ExportToJSON converts the ResponsePayload struct into a JSON string format for API response.
func (r *ResponsePayload) ExportToJSON() (string, error) {
	jsonData, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

// SaveJSONToFile receives a JSON string and saves it to a specified file within the cache directory.
func SaveJSONToFile(fileName string, jsonString string) error {
	// 1. Auto-create the cache directory if it doesn't exist
	err := os.MkdirAll(CacheDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("[ERROR]      Unable to create cache directory: %v", err)
	}

	// 2. Construct the full file path within the cache directory
	filePath := filepath.Join(CacheDir, fileName)

	// 3. Write the JSON string to the target file
	err = os.WriteFile(filePath, []byte(jsonString), 0644)
	if err != nil {
		return fmt.Errorf("[ERROR]      Unable to write JSON file: %v", err)
	}

	fmt.Printf("[BATCH]     API packet successfully saved to: %s\n", filePath)
	return nil
}

// RelayGenerateRequest handles the incoming request to generate a ZKP proof by connecting to the ZKP Service.
func RelayGenerateRequest(payload RequestPayload) ResponsePayload {
	var response ResponsePayload

	fmt.Printf("[BATCH]     Received a Proof signal for X=%d, Y=%d. Forwarding to Service...\n", payload.SecretX, payload.PublicY)

	conn, err := net.Dial("tcp", ServiceAddr)
	if err != nil {
		response.Status = "ERROR"
		response.Message = fmt.Sprintf("[ERROR]     Unable to connect to ZKP Service: %v", err)
		return response
	}
	defer conn.Close()

	pack := fmt.Sprintf("GENERATE|%d|%d", payload.SecretX, payload.PublicY)
	fmt.Fprintf(conn, "%s\n", pack)

	res, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		response.Status = "ERROR"
		response.Message = fmt.Sprintf("[ERROR]     Unable to read response from Service: %v", err)
		return response
	}

	res = strings.TrimSpace(res)

	// FIX LOGIC 1: Using strings.Contains instead of HasPrefix to correctly match "[SUCCESS]" format
	if !strings.Contains(res, "SUCCESS") {
		response.Status = "ERROR"
		response.Message = fmt.Sprintf("[ERROR]     Service rejected the request: %s", res)
		return response
	}

	// FIX LOGIC 2 & 3: Read transient session files from CacheDir and system keys from ConfigDir
	proofBytes, errProof := os.ReadFile(filepath.Join(CacheDir, "proof.data"))
	witnessBytes, errWit := os.ReadFile(filepath.Join(CacheDir, "witness.data"))

	// Read verification key from config directory as a permanent system asset
	vkBytes, errVk := os.ReadFile(filepath.Join(ConfigDir, "verifying.key"))

	if errProof != nil || errVk != nil || errWit != nil {
		response.Status = "ERROR"
		response.Message = fmt.Sprintf("System error: Unable to read ZKP artifacts (Proof err: %v, VK err: %v, Witness err: %v)", errProof, errVk, errWit)
		return response
	}

	response.Status = "SUCCESS"
	response.Message = "Proof generated successfully"
	response.Proof = proofBytes
	response.PublicKey = vkBytes
	response.PublicWitness = witnessBytes

	return response
}
