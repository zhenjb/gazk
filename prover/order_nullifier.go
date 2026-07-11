package prover

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdmimc "github.com/consensys/gnark/std/hash/mimc"
)

// ZK-T06 — Order-nullifier constraint.
//
// Anti replay: a filled/cancelled order must never match again. The chain
// (ONCHAIN-T02/T04) tracks the used-nullifier set; the circuit proves the
// nullifier is correctly derived so the chain only needs the set. The pitfall
// (plan): if the concat order owner||orderHash or the domain tag differ across
// the three parties, they derive DIFFERENT nullifiers and the chain rejects a
// legitimate order. So the derivation is locked identically across all three.
//
// This file delivers BOTH halves of ZK-T06:
//
//  1. Cross-party derivation anchor (v0, WIRE value). OrderNullifierV0 reproduces
//     P3 state.OrderNullifierFor BYTE-EXACT:
//     orderNullifier = SHA256( "zkdex/orderNullifier/v0" | owner | orderHash ).
//     This is the value the chain stores and off-chain computes; the lock test
//     pins it to the published zk_trade_io.md §8 vector so all three parties
//     agree bit-for-bit on the v0 wire nullifier.
//
//  2. In-circuit per-op nullifier template (v1, field-native). Like the trade
//     circuit family (ZK-T03..T05) and the existing withdrawal NullifierCircuitV1,
//     the in-circuit hash is MiMC/BN254, not SHA-256 (SHA-256 in-circuit is
//     expensive; the v1 MiMC nullifier is the zk_trade_io.md §10 migration
//     target). The template takes the op hash as a field element, so it also
//     serves ZK-T08a (withdrawal per-op nullifier). The v0 wire value and the v1
//     in-circuit value are reconciled at the lockstep v0->v1 migration.
const OrderNullifierDomainTagV0 = "zkdex/orderNullifier/v0"

// OrderNullifierV0 derives the v0 (SHA-256) order replay nullifier, byte-exact
// with P3 state.OrderNullifierFor and the chain store (ONCHAIN-T02). owner and
// orderHash are concatenated in that fixed order with '|' separators after the
// domain tag; changing either the order or the tag changes the nullifier.
func OrderNullifierV0(owner, orderHash string) (string, error) {
	owner = strings.TrimSpace(owner)
	orderHash = strings.TrimSpace(orderHash)
	if owner == "" {
		return "", fmt.Errorf("order nullifier: owner is empty")
	}
	if orderHash == "" {
		return "", fmt.Errorf("order nullifier: orderHash is empty")
	}

	var b strings.Builder
	b.WriteString(OrderNullifierDomainTagV0)
	b.WriteByte('|')
	b.WriteString(owner)
	b.WriteByte('|')
	b.WriteString(orderHash)

	sum := sha256.Sum256([]byte(b.String()))
	return "0x" + hex.EncodeToString(sum[:]), nil
}

// OrderNullifierCircuitV1 is the field-native per-op nullifier template:
//
//	orderNullifier = MiMC(ownerField, opHashField)
//	AssertIsEqual(orderNullifier, ExpectedOrderNullifier)
//
// Owner is bound in, so a used order cannot be replayed under another owner.
// opHashField is the op commitment (orderHash) mapped to a field element — the
// same shape ZK-T08a will use for withdrawal op hashes.
type OrderNullifierCircuitV1 struct {
	OwnerField             frontend.Variable
	OpHashField            frontend.Variable
	ExpectedOrderNullifier frontend.Variable `gnark:",public"`
}

func (c *OrderNullifierCircuitV1) Define(api frontend.API) error {
	hasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hasher.Write(c.OwnerField, c.OpHashField)
	computed := hasher.Sum()
	api.AssertIsEqual(computed, c.ExpectedOrderNullifier)
	return nil
}

type OrderNullifierCircuitV1Input struct {
	OwnerField             *big.Int
	OpHashField            *big.Int
	ExpectedOrderNullifier *big.Int
}

// BuildOrderNullifierCircuitV1Input maps (owner, orderHash) into field elements
// and computes the expected field-native nullifier. owner uses the same mapping
// as ZK-T03 (OrderOwnerFieldForV1); orderHash (a 0x hex digest) maps via the
// zk_trade_io.md §5 rule (big-endian bytes mod r).
func BuildOrderNullifierCircuitV1Input(owner, orderHash string) (OrderNullifierCircuitV1Input, error) {
	ownerField, err := OrderOwnerFieldForV1(owner)
	if err != nil {
		return OrderNullifierCircuitV1Input{}, err
	}
	opHashField, err := hexHashToField(orderHash)
	if err != nil {
		return OrderNullifierCircuitV1Input{}, fmt.Errorf("orderHash %q: %w", orderHash, err)
	}
	expected, err := OrderNullifierCircuitV1ForFields(ownerField, opHashField)
	if err != nil {
		return OrderNullifierCircuitV1Input{}, err
	}
	return OrderNullifierCircuitV1Input{
		OwnerField:             ownerField,
		OpHashField:            opHashField,
		ExpectedOrderNullifier: expected,
	}, nil
}

// hexHashToField maps a "0x"-prefixed hash hex string to a BN254 field element
// (big-endian bytes reduced mod r — zk_trade_io.md §5).
func hexHashToField(h string) (*big.Int, error) {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(h, "0x")
	if h == "" {
		return nil, fmt.Errorf("empty hash")
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return bytesToBN254FieldBigInt(raw), nil
}

// OrderNullifierV1FromHashHex returns the field-native v1 nullifier for (owner,
// orderHash) as 0x hex. This is the IN-CIRCUIT value (MiMC), distinct from the
// v0 wire value OrderNullifierV0. (ZK-T03's OrderNullifierCircuitV1Hex derives
// from full order fields; this one takes the orderHash directly — the per-op
// template shape.)
func OrderNullifierV1FromHashHex(owner, orderHash string) (string, error) {
	input, err := BuildOrderNullifierCircuitV1Input(owner, orderHash)
	if err != nil {
		return "", err
	}
	return "0x" + fieldBigIntToHex(input.ExpectedOrderNullifier), nil
}

func orderNullifierAssignment(in OrderNullifierCircuitV1Input) OrderNullifierCircuitV1 {
	return OrderNullifierCircuitV1{
		OwnerField:             in.OwnerField,
		OpHashField:            in.OpHashField,
		ExpectedOrderNullifier: in.ExpectedOrderNullifier,
	}
}

func compileAndSetupOrderNullifierCircuit() (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	var circuit OrderNullifierCircuitV1
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile order nullifier circuit v1: %w", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup order nullifier circuit v1: %w", err)
	}
	return ccs, provingKey, verifyingKey, nil
}

// ProveOrderNullifierCircuitV1 proves the nullifier is correctly derived. It
// fails if ExpectedOrderNullifier does not equal MiMC(owner, opHash) — a forged
// nullifier or a wrong owner.
func ProveOrderNullifierCircuitV1(input OrderNullifierCircuitV1Input) (string, error) {
	ccs, provingKey, _, err := compileAndSetupOrderNullifierCircuit()
	if err != nil {
		return "", err
	}

	assignment := orderNullifierAssignment(input)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("build order nullifier witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove order nullifier circuit v1: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize order nullifier proof: %w", err)
	}
	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}
