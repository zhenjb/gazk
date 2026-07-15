package prover

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

const KeyDirEnv = "GAZK_KEY_DIR"

func configuredKeyDir() string {
	return strings.TrimSpace(os.Getenv(KeyDirEnv))
}

func loadOrSetupGroth16Keys(
	ccs constraint.ConstraintSystem,
	keyDir string,
	keyID string,
) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	if strings.TrimSpace(keyDir) == "" {
		provingKey, verifyingKey, err := groth16.Setup(ccs)
		if err != nil {
			return nil, nil, err
		}

		return provingKey, verifyingKey, nil
	}

	if strings.TrimSpace(keyID) == "" {
		return nil, nil, fmt.Errorf("keyID is required")
	}

	provingKeyPath := filepath.Join(keyDir, keyID+".proving.key")
	verifyingKeyPath := filepath.Join(keyDir, keyID+".verifying.key")

	if fileExists(provingKeyPath) && fileExists(verifyingKeyPath) {
		provingKey, verifyingKey, err := loadGroth16Keys(provingKeyPath, verifyingKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("load groth16 keys %q: %w", keyID, err)
		}

		return provingKey, verifyingKey, nil
	}

	provingKey, verifyingKey, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, err
	}

	if err := saveGroth16Keys(provingKey, verifyingKey, provingKeyPath, verifyingKeyPath); err != nil {
		return nil, nil, fmt.Errorf("save groth16 keys %q: %w", keyID, err)
	}

	return provingKey, verifyingKey, nil
}

// loadOrSetupTradeKeys is a fingerprint-guarded variant of loadOrSetupGroth16Keys
// for the trade circuit (TRD-A2). loadOrSetupGroth16Keys matches persisted keys by
// FILE NAME only, so after a circuit change a leftover gazk-trade-v1.*.key would be
// loaded silently and every proof would fail to verify with no clear cause. Here we
// persist a sidecar fingerprint of the compiled circuit next to the keys; on load,
// if the fingerprint is absent or differs (circuit changed), the stale keys are
// REGENERATED and re-persisted, and a clear warning tells the operator to re-export
// the vk for B. When keyDir is empty, a fresh (ephemeral) setup is used.
func loadOrSetupTradeKeys(
	ccs constraint.ConstraintSystem,
	keyDir string,
	keyID string,
) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	if strings.TrimSpace(keyDir) == "" {
		return groth16.Setup(ccs)
	}
	if strings.TrimSpace(keyID) == "" {
		return nil, nil, fmt.Errorf("keyID is required")
	}

	fingerprint, err := circuitFingerprint(ccs)
	if err != nil {
		return nil, nil, fmt.Errorf("fingerprint trade circuit: %w", err)
	}

	provingKeyPath := filepath.Join(keyDir, keyID+".proving.key")
	verifyingKeyPath := filepath.Join(keyDir, keyID+".verifying.key")
	fingerprintPath := filepath.Join(keyDir, keyID+".circuit.sha256")

	if fileExists(provingKeyPath) && fileExists(verifyingKeyPath) && fileExists(fingerprintPath) {
		stored, rerr := os.ReadFile(fingerprintPath)
		if rerr == nil && strings.TrimSpace(string(stored)) == fingerprint {
			return loadGroth16Keys(provingKeyPath, verifyingKeyPath)
		}
		log.Printf("[gazk] trade circuit fingerprint mismatch for %q — regenerating keys; RE-EXPORT the vk for the chain (gazk export-trade-verifier-artifact)", keyID)
	}

	provingKey, verifyingKey, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, err
	}
	if err := saveGroth16Keys(provingKey, verifyingKey, provingKeyPath, verifyingKeyPath); err != nil {
		return nil, nil, fmt.Errorf("save groth16 keys %q: %w", keyID, err)
	}
	if err := writeFingerprint(fingerprintPath, fingerprint); err != nil {
		return nil, nil, fmt.Errorf("save circuit fingerprint %q: %w", keyID, err)
	}
	return provingKey, verifyingKey, nil
}

// circuitFingerprint is a stable digest of the compiled constraint system. It
// changes iff the circuit changes, so it detects a stale persisted key.
func circuitFingerprint(ccs constraint.ConstraintSystem) (string, error) {
	var buf bytes.Buffer
	if _, err := ccs.WriteTo(&buf); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

func writeFingerprint(path, fingerprint string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(fingerprint+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadGroth16Keys(
	provingKeyPath string,
	verifyingKeyPath string,
) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	provingKey := groth16.NewProvingKey(ecc.BN254)
	verifyingKey := groth16.NewVerifyingKey(ecc.BN254)

	provingFile, err := os.Open(provingKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open proving key: %w", err)
	}
	defer provingFile.Close()

	if _, err := provingKey.ReadFrom(provingFile); err != nil {
		return nil, nil, fmt.Errorf("read proving key: %w", err)
	}

	verifyingFile, err := os.Open(verifyingKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open verifying key: %w", err)
	}
	defer verifyingFile.Close()

	if _, err := verifyingKey.ReadFrom(verifyingFile); err != nil {
		return nil, nil, fmt.Errorf("read verifying key: %w", err)
	}

	return provingKey, verifyingKey, nil
}

func saveGroth16Keys(
	provingKey groth16.ProvingKey,
	verifyingKey groth16.VerifyingKey,
	provingKeyPath string,
	verifyingKeyPath string,
) error {
	if err := os.MkdirAll(filepath.Dir(provingKeyPath), 0o755); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}

	provingTmp := provingKeyPath + ".tmp"
	verifyingTmp := verifyingKeyPath + ".tmp"

	provingFile, err := os.OpenFile(provingTmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create proving key: %w", err)
	}

	if _, err := provingKey.WriteTo(provingFile); err != nil {
		_ = provingFile.Close()
		return fmt.Errorf("write proving key: %w", err)
	}

	if err := provingFile.Close(); err != nil {
		return fmt.Errorf("close proving key: %w", err)
	}

	verifyingFile, err := os.OpenFile(verifyingTmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create verifying key: %w", err)
	}

	if _, err := verifyingKey.WriteTo(verifyingFile); err != nil {
		_ = verifyingFile.Close()
		return fmt.Errorf("write verifying key: %w", err)
	}

	if err := verifyingFile.Close(); err != nil {
		return fmt.Errorf("close verifying key: %w", err)
	}

	if err := os.Rename(provingTmp, provingKeyPath); err != nil {
		return fmt.Errorf("install proving key: %w", err)
	}

	if err := os.Rename(verifyingTmp, verifyingKeyPath); err != nil {
		return fmt.Errorf("install verifying key: %w", err)
	}

	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
