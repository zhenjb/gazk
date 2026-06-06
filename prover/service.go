package prover

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/zhenjb/gazk/contract"
)

const VerificationKeyID = "gazk-smoke-v1"

var (
	ErrInvalidProveRequest = errors.New("invalid prove request")
	ErrInvalidProofBundle  = errors.New("invalid proof bundle")
)

// Service is the P2 prover boundary.
//
// Current stage:
// - contract-compatible smoke prover
// - emits final ProofBundle shape
// - uses deterministic digest as placeholder proof
//
// Later stages replace buildSmokeProof with real gnark proving.
type Service struct{}

func NewService() *Service {
	return &Service{}
}

func (s *Service) Prove(req contract.ProveRequest) (contract.ProofBundle, error) {
	if err := validateProveRequest(req); err != nil {
		return contract.ProofBundle{}, err
	}

	publicInputs := BuildPublicInputs(req.SettlementUpdate, req.BatchCommitments)

	proof, err := buildSmokeProof(req, publicInputs)
	if err != nil {
		return contract.ProofBundle{}, err
	}

	return contract.ProofBundle{
		Proof:             proof,
		PublicInputs:      publicInputs,
		VerificationKeyID: VerificationKeyID,
	}, nil
}

func (s *Service) Verify(req contract.VerifyRequest) error {
	expectedPublicInputs := BuildPublicInputs(req.SettlementUpdate, req.BatchCommitments)

	if len(req.ProofBundle.PublicInputs) != 6 {
		return fmt.Errorf("%w: publicInputs must contain 6 values", ErrInvalidProofBundle)
	}

	for i := range expectedPublicInputs {
		if req.ProofBundle.PublicInputs[i] != expectedPublicInputs[i] {
			return fmt.Errorf(
				"%w: publicInputs[%d] mismatch: got %q, expected %q",
				ErrInvalidProofBundle,
				i,
				req.ProofBundle.PublicInputs[i],
				expectedPublicInputs[i],
			)
		}
	}

	if req.ProofBundle.VerificationKeyID != VerificationKeyID {
		return fmt.Errorf(
			"%w: verificationKeyId mismatch: got %q, expected %q",
			ErrInvalidProofBundle,
			req.ProofBundle.VerificationKeyID,
			VerificationKeyID,
		)
	}

	if req.ProofBundle.Proof == "" {
		return fmt.Errorf("%w: proof is empty", ErrInvalidProofBundle)
	}

	return nil
}

func BuildPublicInputs(
	update contract.SettlementUpdate,
	commitments contract.BatchCommitments,
) []string {
	return []string{
		update.OldStateRoot,
		update.NewStateRoot,
		commitments.DepositsRoot,
		commitments.WithdrawalsRoot,
		commitments.NullifiersRoot,
		commitments.WithdrawOutputsRoot,
	}
}

func validateProveRequest(req contract.ProveRequest) error {
	if req.SettlementUpdate.BatchID == "" {
		return fmt.Errorf("%w: settlementUpdate.batchId is required", ErrInvalidProveRequest)
	}

	if req.SettlementUpdate.OldStateRoot == "" {
		return fmt.Errorf("%w: settlementUpdate.oldStateRoot is required", ErrInvalidProveRequest)
	}

	if req.SettlementUpdate.NewStateRoot == "" {
		return fmt.Errorf("%w: settlementUpdate.newStateRoot is required", ErrInvalidProveRequest)
	}

	if req.BatchCommitments.DepositsRoot == "" {
		return fmt.Errorf("%w: batchCommitments.depositsRoot is required", ErrInvalidProveRequest)
	}

	if req.BatchCommitments.WithdrawalsRoot == "" {
		return fmt.Errorf("%w: batchCommitments.withdrawalsRoot is required", ErrInvalidProveRequest)
	}

	if req.BatchCommitments.NullifiersRoot == "" {
		return fmt.Errorf("%w: batchCommitments.nullifiersRoot is required", ErrInvalidProveRequest)
	}

	if req.BatchCommitments.WithdrawOutputsRoot == "" {
		return fmt.Errorf("%w: batchCommitments.withdrawOutputsRoot is required", ErrInvalidProveRequest)
	}

	if len(req.Witness.Accounts) == 0 {
		return fmt.Errorf("%w: witness.accounts is required", ErrInvalidProveRequest)
	}

	return nil
}

func buildSmokeProof(req contract.ProveRequest, publicInputs []string) (string, error) {
	payload := struct {
		SettlementUpdate contract.SettlementUpdate `json:"settlementUpdate"`
		BatchCommitments contract.BatchCommitments `json:"batchCommitments"`
		Witness          contract.Witness          `json:"witness"`
		PublicInputs     []string                  `json:"publicInputs"`
	}{
		SettlementUpdate: req.SettlementUpdate,
		BatchCommitments: req.BatchCommitments,
		Witness:          req.Witness,
		PublicInputs:     publicInputs,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(raw)
	return "0x" + hex.EncodeToString(sum[:]), nil
}
