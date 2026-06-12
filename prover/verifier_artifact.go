package prover

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/consensys/gnark/backend/groth16"

	"github.com/zhenjb/gazk/contract"
)

const (
	VerifierArtifactCurve   = "BN254"
	VerifierArtifactBackend = "groth16"
)

var SettlementPublicInputNames = []string{
	"settlementUpdate.oldStateRoot",
	"settlementUpdate.newStateRoot",
	"batchCommitments.depositsRoot",
	"batchCommitments.withdrawalsRoot",
	"batchCommitments.nullifiersRoot",
	"batchCommitments.withdrawOutputsRoot",
}

func (s *Service) VerifierArtifact() (contract.VerifierArtifact, error) {
	if s.hashModeErr != nil {
		return contract.VerifierArtifact{}, s.hashModeErr
	}

	if s.engineErr != nil {
		return contract.VerifierArtifact{}, s.engineErr
	}

	verifyingKey, err := s.verifyingKey()
	if err != nil {
		return contract.VerifierArtifact{}, err
	}

	verifyingKeyHex, err := encodeVerifyingKeyHex(verifyingKey)
	if err != nil {
		return contract.VerifierArtifact{}, err
	}

	return contract.VerifierArtifact{
		VerificationKeyID: s.VerificationKeyID(),
		HashMode:          s.HashMode().String(),
		Curve:             VerifierArtifactCurve,
		Backend:           VerifierArtifactBackend,
		PublicInputCount:  len(SettlementPublicInputNames),
		PublicInputNames:  append([]string(nil), SettlementPublicInputNames...),
		VerifyingKey:      verifyingKeyHex,
	}, nil
}

func (s *Service) verifyingKey() (groth16.VerifyingKey, error) {
	switch s.HashMode() {
	case HashModeV1MiMC:
		if s.settlementV1Engine == nil {
			return nil, fmt.Errorf("settlement v1 engine is not initialized")
		}
		return s.settlementV1Engine.VerifyingKey(), nil

	case HashModeV0SHA256:
		if s.balanceEngine == nil {
			return nil, fmt.Errorf("balance engine is not initialized")
		}
		return s.balanceEngine.VerifyingKey(), nil

	default:
		return nil, fmt.Errorf("%w: unsupported hash mode %q", ErrInvalidProveRequest, s.HashMode())
	}
}

func encodeVerifyingKeyHex(verifyingKey groth16.VerifyingKey) (string, error) {
	if verifyingKey == nil {
		return "", fmt.Errorf("verifying key is nil")
	}

	var buf bytes.Buffer
	if _, err := verifyingKey.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize verifying key: %w", err)
	}

	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}
