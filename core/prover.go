package core

import (
	"fmt"
	"gazk/circuit"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Define clear boundaries for system assets vs temporary session data
const (
	ConfigDir = "config" // Stores: circuit.r1cs, proving.key, verifying.key
	CacheDir  = "cache"  // Stores: proof.data, witness.data, api.json
)

// SetupSystem compiles the arithmetic circuit and generates permanent system keys.
func SetupSystem() error {
	var myCircuit circuit.CubicCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		return err
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return err
	}

	// Save core system assets to the permanent "config" directory
	if err := saveFile(ConfigDir, "circuit.r1cs", ccs); err != nil {
		return err
	}
	if err := saveFile(ConfigDir, "proving.key", pk); err != nil {
		return err
	}
	if err := saveFile(ConfigDir, "verifying.key", vk); err != nil {
		return err
	}

	fmt.Println("[CORE]     Setup and Key Generation completed. Permanent assets saved to config.")
	return nil
}

// GenerateProof computes the ZKP proof and outputs transient artifacts to the cache directory.
func GenerateProof(secretX int64, publicY int64) error {
	ccs := groth16.NewCS(ecc.BN254)
	if err := loadFile(ConfigDir, "circuit.r1cs", ccs); err != nil {
		return err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := loadFile(ConfigDir, "proving.key", pk); err != nil {
		return err
	}

	// Create Witness with the provided secret and public values
	assignment := circuit.CubicCircuit{X: secretX, Y: publicY}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}

	// Create Proof using the Proving Key and Witness
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return err
	}

	// Extract the public witness part
	pubWitness, _ := witness.Public()

	// FIX LOGIC 1 & 2: Output transient session artifacts to "cache" directory with synchronized file names
	if err := saveFile(CacheDir, "proof.data", proof); err != nil {
		return err
	}
	if err := saveFile(CacheDir, "witness.data", pubWitness); err != nil {
		return err
	}

	fmt.Printf("[CORE]     Proof generated for (X:%d, Y:%d) and saved to cache.\n", secretX, publicY)
	return nil
}

// VerifyProof verifies the generated proof against the verifying key and public witness.
func VerifyProof() (bool, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := loadFile(ConfigDir, "verifying.key", vk); err != nil {
		return false, err
	}
	proof := groth16.NewProof(ecc.BN254)
	if err := loadFile(CacheDir, "proof.data", proof); err != nil {
		return false, err
	}
	pubWitness, _ := frontend.NewWitness(nil, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err := loadFile(CacheDir, "witness.data", pubWitness); err != nil {
		return false, err
	}

	err := groth16.Verify(proof, vk, pubWitness)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// Helper function to save ZKP objects into a specified directory
func saveFile(dirName string, fileName string, obj io.WriterTo) error {
	_ = os.MkdirAll(dirName, os.ModePerm)

	file, err := os.Create(filepath.Join(dirName, fileName))
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = obj.WriteTo(file)
	return err
}

// Helper function to load ZKP objects from a specified directory
func loadFile(dirName string, fileName string, obj io.ReaderFrom) error {
	file, err := os.Open(filepath.Join(dirName, fileName))
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = obj.ReadFrom(file)
	return err
}

// ClearAllSessionData wipes out temporary transaction data from both config and cache folders without destroying system keys.
func ClearAllSessionData() {
	targetDirs := []string{ConfigDir, CacheDir}

	for _, dir := range targetDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		files, err := os.ReadDir(dir)
		if err != nil {
			fmt.Printf("[ERROR]    Unable to read folder %s: %v\n", dir, err)
			continue
		}

		for _, file := range files {
			fname := file.Name()

			// KEY PROTECTION RULE: Wipe out session trade records or result APIs
			// Never delete proving.key, verifying.key, or circuit.r1cs inside ConfigDir
			if strings.Contains(fname, "proof") || strings.Contains(fname, "witness") || strings.Contains(fname, "api.json") {
				filePath := filepath.Join(dir, fname)
				if err := os.Remove(filePath); err != nil {
					fmt.Printf("[ERROR]    Unable to remove junk file: %s\n", filePath)
				}
			}
		}
	}
	fmt.Println("[CORE]     Session data and temporary artifacts cleared successfully.")
}
