package prover

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/zhenjb/gazk/contract"
)

const (
	VerificationKeyID   = "gazk-balance-smoke-v1"
	VerificationKeyIDV1 = "gazk-settlement-v1-mimc-nullifier-smoke-v1"
)

var (
	ErrInvalidProveRequest = errors.New("invalid prove request")
	ErrInvalidProofBundle  = errors.New("invalid proof bundle")
)

// Service is the P2 prover boundary.
//
// Current stage:
// - v0-sha256: balance smoke circuit + service-level v0 hash bindings
// - v1-mimc: combined settlement v1 circuit with balance + nullifier constraint
// - destinationHash remains service-level validated in v1
//
// Later stages will bind destination hash, state roots, and the 6 settlement
// public inputs inside the circuit.
type Service struct {
	balanceEngine      *BalanceTransitionEngine
	settlementV1Engine *SettlementCircuitV1Engine
	engineErr          error
	hashMode           HashMode
	hashModeErr        error

	// ZK-T09 unified trade circuit engine (pk/vk under vkId gazk-trade-v1).
	// Lazily initialised: compiling + setup is expensive and only needed when a
	// caller actually verifies a trade proof or exports the trade verifier
	// artifact, so most Service constructions (core deposit/withdraw) skip it.
	tradeEngineOnce sync.Once
	tradeEngineVal  *TradeCircuitEngine
	tradeEngineErr  error
}

// tradeEngine lazily compiles the unified trade circuit and loads/sets up its
// Groth16 keys (ZK-T09).
func (s *Service) tradeEngine() (*TradeCircuitEngine, error) {
	s.tradeEngineOnce.Do(func() {
		s.tradeEngineVal, s.tradeEngineErr = NewTradeCircuitEngine()
	})
	return s.tradeEngineVal, s.tradeEngineErr
}

func NewService() *Service {
	return NewServiceWithHashMode(os.Getenv("GAZK_HASH_MODE"))
}

func NewServiceWithHashMode(rawHashMode string) *Service {
	mode, modeErr := ParseHashMode(rawHashMode)

	service := &Service{
		hashMode:    mode,
		hashModeErr: modeErr,
	}

	if modeErr != nil {
		return service
	}

	switch mode {
	case HashModeV1MiMC:
		engine, err := NewSettlementCircuitV1Engine()
		service.settlementV1Engine = engine
		service.engineErr = err
	default:
		engine, err := NewBalanceTransitionEngine()
		service.balanceEngine = engine
		service.engineErr = err
	}

	return service
}

func (s *Service) HashMode() HashMode {
	if s.hashMode == "" {
		return DefaultHashMode
	}
	return s.hashMode
}

func (s *Service) VerificationKeyID() string {
	switch s.HashMode() {
	case HashModeV1MiMC:
		return VerificationKeyIDV1
	default:
		return VerificationKeyID
	}
}

func (s *Service) Prove(req contract.ProveRequest) (contract.ProofBundle, error) {
	// ZK-T10: a trade batch routes to the unified trade circuit. Core
	// deposit/withdraw batches (Trade == nil) fall through to the existing path,
	// so their contract is unchanged.
	if req.Trade != nil {
		return s.ProveTrade(*req.Trade)
	}

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

	proof, err := s.buildProof(req)
	if err != nil {
		return contract.ProofBundle{}, err
	}

	return contract.ProofBundle{
		Proof:             proof,
		PublicInputs:      publicInputs,
		VerificationKeyID: s.VerificationKeyID(),
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

	if req.ProofBundle.VerificationKeyID != s.VerificationKeyID() {
		return fmt.Errorf(
			"%w: verificationKeyId mismatch: got %q, expected %q",
			ErrInvalidProofBundle,
			req.ProofBundle.VerificationKeyID,
			s.VerificationKeyID(),
		)
	}

	return s.verifyProof(req)
}

func (s *Service) buildProof(req contract.ProveRequest) (string, error) {
	switch s.HashMode() {
	case HashModeV1MiMC:
		return s.settlementV1Engine.BuildProof(req)
	default:
		return s.balanceEngine.BuildProof(req)
	}
}

func (s *Service) verifyProof(req contract.VerifyRequest) error {
	switch s.HashMode() {
	case HashModeV1MiMC:
		return s.settlementV1Engine.VerifyProof(req)
	default:
		return s.balanceEngine.VerifyProof(req.ProofBundle.Proof)
	}
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
		if err := validateNullifierBindingV1(req); err != nil {
			return err
		}
		if err := validateDestinationHashBindingV1(req); err != nil {
			return err
		}
		return nil

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
