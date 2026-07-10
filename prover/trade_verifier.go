package prover

import (
	"errors"
	"fmt"
	"strings"

	"github.com/zhenjb/gazk/contract"
)

// ZK-T02 — STUB trade verifier.
//
//	==================  STUB — ACCEPT-ANY — NOT REAL SECURITY  ==================
//
// This file delivers a FAKE trade verifier with the EXACT signature the real
// (Wave 2) verifier will have, so P1 (chain: SubmitBatchProof / ONCHAIN-T04) and
// P4 (relayer: settle_loop) can wire the full build->prove->submit->verify
// pipeline NOW, months before the real trade circuit (ZK-T03..T09) exists.
//
// VerifyTrade performs ONLY cheap STRUCTURAL checks (proof non-empty, exactly 8
// public inputs in the locked layout, vkId == gazk-trade-v1, prover-claimed
// inputs bind to caller-reconstructed inputs) and then returns nil. It does NOT
// run any cryptographic verification — a syntactically well-formed proof of a
// FALSE statement is accepted. Do not rely on this for any safety property.
//
// Wave 2 swaps the body of VerifyTrade for a real Groth16 verify against the
// gazk-trade-v1 verifying key WITHOUT changing this signature, so no caller in
// P1/P4 needs to change (the ZK-T02 anti-drift contract).
const (
	// TradeVerificationKeyID is the PUBLISHED vkId for the trade circuit. P1/P4
	// hardcode this now; ZK-T09 produces the real key under the same id.
	TradeVerificationKeyID = "gazk-trade-v1"

	// TradePublicInputCount is the locked size of the extended trade public-input
	// vector: core [0..5] + [6]=tradesRoot + [7]=ordersRoot (zk_trade_io.md §6).
	TradePublicInputCount = 8
)

// TradePublicInputNames is the LOCKED order of the 8 trade public inputs. It
// mirrors ganc-sys internal/batch.PublicInputLabelsWithTrades() exactly — same
// order, append-not-reorder. Any change here is a breaking contract change that
// must bump the vkId and be coordinated across P1/P3/P4.
var TradePublicInputNames = []string{
	"settlementUpdate.oldStateRoot",
	"settlementUpdate.newStateRoot",
	"batchCommitments.depositsRoot",
	"batchCommitments.withdrawalsRoot",
	"batchCommitments.nullifiersRoot",
	"batchCommitments.withdrawOutputsRoot",
	"batchCommitments.tradesRoot",
	"batchCommitments.ordersRoot",
}

// ErrTradeProofRejected is returned by the stub when a proof bundle fails the
// structural checks. The real verifier reuses the same sentinel for a failed
// cryptographic verification, so callers can match on it across the swap.
var ErrTradeProofRejected = errors.New("trade proof rejected")

// VerifyTrade is the LOCKED trade-verifier entry point.
//
// Parameters (matched to the real Wave-2 verifier — do not reorder):
//   - update:       the settlement batch context (used for basic sanity now,
//     Merkle/root binding in Wave 2).
//   - proofBundle:  the prover output — proof bytes, prover-claimed public
//     inputs, and vkId.
//   - publicInputs: the 8 public inputs the CALLER reconstructed independently
//     from the on-chain batch (the "expected" values). gazk cannot rebuild these
//     itself because contract.SettlementUpdate does not carry trades, so the
//     caller supplies them (zk_trade_io.md §6 layout).
//
// STUB behaviour: structural accept-any. Returns nil (accept) when the bundle is
// well-formed; returns ErrTradeProofRejected otherwise. NEVER treat a nil return
// as cryptographic soundness until Wave 2.
func (s *Service) VerifyTrade(
	update contract.SettlementUpdate,
	proofBundle contract.ProofBundle,
	publicInputs []string,
) error {
	// 1. Proof bytes must be present. An empty proof is the canonical "no proof"
	//    signal the stub must reject (plan DoD: accept/reject by non-empty).
	if strings.TrimSpace(proofBundle.Proof) == "" {
		return fmt.Errorf("%w: proof is empty", ErrTradeProofRejected)
	}

	// 2. The caller-reconstructed public inputs must be the locked 8-vector,
	//    each a non-empty 0x hex value.
	if err := validateTradePublicInputs("publicInputs", publicInputs); err != nil {
		return err
	}

	// 3. The prover-claimed public inputs must also be the locked 8-vector and
	//    must bind element-wise to the caller's reconstruction. This is exactly
	//    the check the real verifier performs before Groth16.Verify, so wiring it
	//    now catches layout/order drift between P3/P4 and A early.
	if err := validateTradePublicInputs("proofBundle.publicInputs", proofBundle.PublicInputs); err != nil {
		return err
	}
	for i := range publicInputs {
		if proofBundle.PublicInputs[i] != publicInputs[i] {
			return fmt.Errorf(
				"%w: publicInputs[%d] (%s) mismatch: proof claims %q, caller expects %q",
				ErrTradeProofRejected,
				i,
				TradePublicInputNames[i],
				proofBundle.PublicInputs[i],
				publicInputs[i],
			)
		}
	}

	// 4. The vkId must be the published trade key id so P1/P4 select the right
	//    verifier. This is the vkId contract A publishes in ZK-T02.
	if proofBundle.VerificationKeyID != TradeVerificationKeyID {
		return fmt.Errorf(
			"%w: verificationKeyId mismatch: got %q, expected %q",
			ErrTradeProofRejected,
			proofBundle.VerificationKeyID,
			TradeVerificationKeyID,
		)
	}

	// 5. Minimal batch-context sanity. The real verifier binds these into the
	//    proof; the stub only checks they are present so an empty update is
	//    rejected rather than silently accepted.
	if strings.TrimSpace(update.OldStateRoot) == "" || strings.TrimSpace(update.NewStateRoot) == "" {
		return fmt.Errorf("%w: settlementUpdate state roots are required", ErrTradeProofRejected)
	}

	// STUB: no cryptographic verification. Accept.
	return nil
}

// TradeVerifierArtifact returns the portable verifier-side contract for the
// trade circuit: the published vkId and the locked 8 public-input names/count.
//
// STUB: VerifyingKey is empty and Stub is true — the real verifying-key bytes
// land in ZK-T09. P1 uses this to bind the public-input layout + vkId now.
func (s *Service) TradeVerifierArtifact() contract.TradeVerifierArtifact {
	return contract.TradeVerifierArtifact{
		VerificationKeyID: TradeVerificationKeyID,
		Curve:             VerifierArtifactCurve,
		Backend:           VerifierArtifactBackend,
		PublicInputCount:  TradePublicInputCount,
		PublicInputNames:  append([]string(nil), TradePublicInputNames...),
		Stub:              true,
	}
}

func validateTradePublicInputs(label string, publicInputs []string) error {
	if len(publicInputs) != TradePublicInputCount {
		return fmt.Errorf(
			"%w: %s must contain %d values, got %d",
			ErrTradeProofRejected,
			label,
			TradePublicInputCount,
			len(publicInputs),
		)
	}

	for i, value := range publicInputs {
		value = strings.TrimSpace(value)
		if value == "" {
			return fmt.Errorf("%w: %s[%d] (%s) is empty", ErrTradeProofRejected, label, i, TradePublicInputNames[i])
		}
		if !strings.HasPrefix(value, "0x") {
			return fmt.Errorf("%w: %s[%d] (%s) must have 0x prefix", ErrTradeProofRejected, label, i, TradePublicInputNames[i])
		}
		if value == "0x" {
			return fmt.Errorf("%w: %s[%d] (%s) must not be empty hex", ErrTradeProofRejected, label, i, TradePublicInputNames[i])
		}
	}

	return nil
}
