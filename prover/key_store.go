package prover

import (
	"fmt"
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
