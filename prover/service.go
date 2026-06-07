package prover

import (
	"errors"
	"fmt"
	"os"

	"github.com/zhenjb/gazk/contract"
)

const VerificationKeyID = "gazk-balance-smoke-v1"

var (
	ErrInvalidProveRequest = errors.New("invalid prove request")
	ErrInvalidProofBundle  = errors.New("invalid proof bundle")
)

// Service is the P2 prover boundary.
//
// Current stage:
// - contract-compatible prover
// - emits final ProofBundle shape
// - runs a real gnark Groth16 smoke circuit for balance transition
// - validates nullifier binding at service layer using the current GANC placeholder hash
// - validates destinationHash binding at service layer using the current GANC placeholder hash
// - verifies Groth16 proof bytes in /verify
// - exposes hash mode contract; default remains v0-sha256 for ganc-sys compatibility
//
// Later stages will bind nullifier, destination hash, state roots, and the
// 6 settlement public inputs inside the circuit.
type Service struct {
	balanceEngine *BalanceTransitionEngine
	engineErr     error
	hashMode      HashMode
	hashModeErr   error
}

func NewService() *Service {
	return NewServiceWithHashMode(os.Getenv("GAZK_HASH_MODE"))
}

func NewServiceWithHashMode(rawHashMode string) *Service {
	mode, modeErr := ParseHashMode(rawHashMode)

	engine, err := NewBalanceTransitionEngine()
	return &Service{
		balanceEngine: engine,
		engineErr:     err,
		hashMode:      mode,
		hashModeErr:   modeErr,
	}
}

func (s *Service) HashMode() HashMode {
	if s.hashMode == "" {
		return DefaultHashMode
	}
	return s.hashMode
}

func (s *Service) Prove(req contract.ProveRequest) (contract.ProofBundle, error) {
	if s.hashModeErr != nil {
		return contract.ProofBundle{}, s.hashModeErr
	}

	if s.engineErr != nil {
		return contract.ProofBundle{}, s.engineErr
	}

	if err := validateProveRequest(req); err != nil {
		return contract.ProofBundle{}, err
	}

	if err := validateSettlementPublicFields(req.SettlementUpdate, req.BatchCommitments); err != nil {
		return contract.ProofBundle{}, err
	}

	if err := s.validateHashBindings(req); err != nil {
		return contract.ProofBundle{}, err
	}

	publicInputs := BuildPublicInputs(req.SettlementUpdate, req.BatchCommitments)

	proof, err := s.balanceEngine.BuildProof(req)
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
	if s.hashModeErr != nil {
		return s.hashModeErr
	}

	if s.engineErr != nil {
		return s.engineErr
	}

	if err := validateSettlementPublicFields(req.SettlementUpdate, req.BatchCommitments); err != nil {
		return err
	}

	expectedPublicInputs := BuildPublicInputs(req.SettlementUpdate, req.BatchCommitments)

	if err := validateProofBundlePublicInputs(req.ProofBundle.PublicInputs); err != nil {
		return err
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

	if err := s.balanceEngine.VerifyProof(req.ProofBundle.Proof); err != nil {
		return err
	}

	return nil
}

func (s *Service) validateHashBindings(req contract.ProveRequest) error {
	switch s.HashMode() {
	case HashModeV0SHA256:
		if err := validateNullifierBinding(req); err != nil {
			return err
		}
		if err := validateDestinationHashBinding(req); err != nil {
			return err
		}
		return nil

	case HashModeV1MiMC:
		// D1-B only locks the hash mode contract. It intentionally does not
		// switch /prove to v1 yet because ganc-sys still emits v0 SHA-256
		// nullifier and destinationHash values.
		return fmt.Errorf("%w: hash mode %q is defined but not enabled for /prove yet", ErrInvalidProveRequest, s.HashMode())

	default:
		return fmt.Errorf("%w: unsupported hash mode %q", ErrInvalidProveRequest, s.HashMode())
	}
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
