package prover

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhenjb/gazk/contract"
)

func TestBalanceEnginePersistsAndReloadsKeys(t *testing.T) {
	keyDir := t.TempDir()

	t.Setenv(KeyDirEnv, keyDir)

	first, err := NewBalanceTransitionEngine()
	if err != nil {
		t.Fatalf("create first balance engine: %v", err)
	}

	if first == nil {
		t.Fatalf("expected first engine")
	}

	provingKeyPath := filepath.Join(keyDir, VerificationKeyID+".proving.key")
	verifyingKeyPath := filepath.Join(keyDir, VerificationKeyID+".verifying.key")

	assertFileExists(t, provingKeyPath)
	assertFileExists(t, verifyingKeyPath)

	firstProvingInfo, err := os.Stat(provingKeyPath)
	if err != nil {
		t.Fatalf("stat first proving key: %v", err)
	}

	second, err := NewBalanceTransitionEngine()
	if err != nil {
		t.Fatalf("create second balance engine: %v", err)
	}

	if second == nil {
		t.Fatalf("expected second engine")
	}

	secondProvingInfo, err := os.Stat(provingKeyPath)
	if err != nil {
		t.Fatalf("stat second proving key: %v", err)
	}

	if secondProvingInfo.Size() != firstProvingInfo.Size() {
		t.Fatalf("expected persisted proving key size to remain stable: first=%d second=%d", firstProvingInfo.Size(), secondProvingInfo.Size())
	}
}

func TestSettlementV1EnginePersistsAndReloadsKeys(t *testing.T) {
	keyDir := t.TempDir()

	t.Setenv(KeyDirEnv, keyDir)

	first, err := NewSettlementCircuitV1Engine()
	if err != nil {
		t.Fatalf("create first settlement v1 engine: %v", err)
	}

	if first == nil {
		t.Fatalf("expected first engine")
	}

	provingKeyPath := filepath.Join(keyDir, VerificationKeyIDV1+".proving.key")
	verifyingKeyPath := filepath.Join(keyDir, VerificationKeyIDV1+".verifying.key")

	assertFileExists(t, provingKeyPath)
	assertFileExists(t, verifyingKeyPath)

	second, err := NewSettlementCircuitV1Engine()
	if err != nil {
		t.Fatalf("create second settlement v1 engine: %v", err)
	}

	if second == nil {
		t.Fatalf("expected second engine")
	}
}

func TestServiceWithPersistedKeysCanProveAndVerifyV0(t *testing.T) {
	keyDir := t.TempDir()

	service := serviceWithKeyDir(t, keyDir, HashModeV0SHA256.String())

	req := validAliceProveRequest()

	proofBundle, err := service.Prove(req)
	if err != nil {
		t.Fatalf("prove with persisted v0 keys: %v", err)
	}

	err = service.Verify(validVerifyRequest(req, proofBundle))
	if err != nil {
		t.Fatalf("verify with persisted v0 keys: %v", err)
	}

	assertFileExists(t, filepath.Join(keyDir, VerificationKeyID+".proving.key"))
	assertFileExists(t, filepath.Join(keyDir, VerificationKeyID+".verifying.key"))
}

func TestServiceWithPersistedKeysCanProveAndVerifyV1(t *testing.T) {
	keyDir := t.TempDir()

	service := serviceWithKeyDir(t, keyDir, HashModeV1MiMC.String())

	req := validAliceProveRequestV1()

	proofBundle, err := service.Prove(req)
	if err != nil {
		t.Fatalf("prove with persisted v1 keys: %v", err)
	}

	err = service.Verify(validVerifyRequest(req, proofBundle))
	if err != nil {
		t.Fatalf("verify with persisted v1 keys: %v", err)
	}

	assertFileExists(t, filepath.Join(keyDir, VerificationKeyIDV1+".proving.key"))
	assertFileExists(t, filepath.Join(keyDir, VerificationKeyIDV1+".verifying.key"))
}

func serviceWithKeyDir(t *testing.T, keyDir string, hashMode string) *Service {
	t.Helper()

	oldKeyDir := os.Getenv(KeyDirEnv)
	t.Setenv(KeyDirEnv, keyDir)

	service := NewServiceWithHashMode(hashMode)

	t.Setenv(KeyDirEnv, oldKeyDir)

	return service
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected file %s to exist: %v", path, err)
	}

	if info.IsDir() {
		t.Fatalf("expected %s to be file, got directory", path)
	}

	if info.Size() == 0 {
		t.Fatalf("expected %s to be non-empty", path)
	}
}

func validVerifyRequest(req contract.ProveRequest, proofBundle contract.ProofBundle) contract.VerifyRequest {
	return contract.VerifyRequest{
		SettlementUpdate: req.SettlementUpdate,
		BatchCommitments: req.BatchCommitments,
		ProofBundle:      proofBundle,
	}
}
