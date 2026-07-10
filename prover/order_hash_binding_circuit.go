package prover

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	bn254mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdmimc "github.com/consensys/gnark/std/hash/mimc"
)

// ZK-T03 — Order signature constraint (hash-binding MVP).
//
// OrderHashBindingCircuitV1 is the field-native order-hash-binding prototype. It
// proves, for one order:
//
//	orderCommitment = MiMC(ownerField, marketField, sideField, priceField,
//	                       qtyField, expiryField, nonceField)
//	orderNullifier  = MiMC(ownerField, orderCommitment)
//
// and AssertIsEqual both against the expected values carried in the witness.
//
//	================  MVP SECURITY ASSUMPTION — READ THIS  ================
//
// This circuit does NOT verify the owner's ECDSA/secp256k1 signature in-circuit
// (that is expensive; see plan ZK-T03). It is the HASH-BINDING option: the order
// canonical fields are bound to orderCommitment, and `owner` is bound into BOTH
// orderCommitment (as a hash input) and orderNullifier — so a signature/order of
// one owner cannot be replayed under a different owner (the recomputed
// commitment + nullifier would differ and AssertIsEqual would fail). The actual
// ECDSA signature validity is checked OFF-CHAIN at STATE-T03 (order validation).
// The proof therefore covers order-integrity + owner-binding, NOT signature
// verification. Do not read a passing proof as "signature verified in ZK".
//
// Consistency with ZK-T01: the LOCKED v0 wire encoding uses SHA-256
// (orderHash/orderNullifier hex). This circuit uses the field-native v1 MiMC
// binding — the migration target documented in zk_trade_io.md §10. The v1
// orderCommitment intentionally DIFFERS from the v0 SHA-256 orderHash; the two
// are reconciled at the v0->v1 lockstep migration, not byte-for-byte here.
//
// Like NullifierCircuitV1 / DestinationHashCircuitV1, this is a standalone
// prototype and is intentionally NOT wired into /prove yet.
type OrderHashBindingCircuitV1 struct {
	// Private canonical order fields (mapped to BN254 field elements by the
	// service preprocessing helpers below).
	OwnerField  frontend.Variable
	MarketField frontend.Variable
	SideField   frontend.Variable
	PriceField  frontend.Variable
	QtyField    frontend.Variable
	ExpiryField frontend.Variable
	NonceField  frontend.Variable

	// Public commitments the circuit binds to.
	ExpectedOrderCommitment frontend.Variable `gnark:",public"`
	ExpectedOrderNullifier  frontend.Variable `gnark:",public"`
}

func (c *OrderHashBindingCircuitV1) Define(api frontend.API) error {
	commitmentHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	commitmentHasher.Write(
		c.OwnerField,
		c.MarketField,
		c.SideField,
		c.PriceField,
		c.QtyField,
		c.ExpiryField,
		c.NonceField,
	)
	orderCommitment := commitmentHasher.Sum()
	api.AssertIsEqual(orderCommitment, c.ExpectedOrderCommitment)

	// Bind owner into the nullifier: orderNullifier = MiMC(owner, orderCommitment).
	nullifierHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	nullifierHasher.Write(c.OwnerField, orderCommitment)
	orderNullifier := nullifierHasher.Sum()
	api.AssertIsEqual(orderNullifier, c.ExpectedOrderNullifier)

	return nil
}

// OrderFieldsV1 is the canonical order the circuit binds, in string form (the
// same seven fields locked in zk_trade_io.md §2, signature excluded).
type OrderFieldsV1 struct {
	Owner  string
	Market string
	Side   string // "buy" | "sell" (case-insensitive)
	Price  string
	Qty    string
	Expiry string
	Nonce  string
}

type OrderHashBindingCircuitV1Input struct {
	OwnerField  *big.Int
	MarketField *big.Int
	SideField   *big.Int
	PriceField  *big.Int
	QtyField    *big.Int
	ExpiryField *big.Int
	NonceField  *big.Int

	ExpectedOrderCommitment *big.Int
	ExpectedOrderNullifier  *big.Int
}

// Domain tags for the field-native v1 order mapping. Locked here; any change is a
// breaking v1 contract change (bump alongside zk_trade_io.md §10).
const (
	OrderOwnerFieldDomainTagV1  = "zkdex/order/ownerField/v1"
	OrderMarketFieldDomainTagV1 = "zkdex/order/marketField/v1"
)

func BuildOrderHashBindingCircuitV1Input(order OrderFieldsV1) (OrderHashBindingCircuitV1Input, error) {
	ownerField, err := OrderOwnerFieldForV1(order.Owner)
	if err != nil {
		return OrderHashBindingCircuitV1Input{}, err
	}
	marketField, err := OrderMarketFieldForV1(order.Market)
	if err != nil {
		return OrderHashBindingCircuitV1Input{}, err
	}
	sideField, err := orderSideFieldV1(order.Side)
	if err != nil {
		return OrderHashBindingCircuitV1Input{}, err
	}
	priceField, err := parseNonNegativeOrderField(order.Price, "price")
	if err != nil {
		return OrderHashBindingCircuitV1Input{}, err
	}
	qtyField, err := parseNonNegativeOrderField(order.Qty, "qty")
	if err != nil {
		return OrderHashBindingCircuitV1Input{}, err
	}
	expiryField, err := parseNonNegativeOrderField(order.Expiry, "expiry")
	if err != nil {
		return OrderHashBindingCircuitV1Input{}, err
	}
	nonceField, err := parseNonNegativeOrderField(order.Nonce, "nonce")
	if err != nil {
		return OrderHashBindingCircuitV1Input{}, err
	}

	orderCommitment, err := OrderCommitmentCircuitV1ForFields(
		ownerField, marketField, sideField, priceField, qtyField, expiryField, nonceField,
	)
	if err != nil {
		return OrderHashBindingCircuitV1Input{}, err
	}

	orderNullifier, err := OrderNullifierCircuitV1ForFields(ownerField, orderCommitment)
	if err != nil {
		return OrderHashBindingCircuitV1Input{}, err
	}

	return OrderHashBindingCircuitV1Input{
		OwnerField:              ownerField,
		MarketField:             marketField,
		SideField:               sideField,
		PriceField:              priceField,
		QtyField:                qtyField,
		ExpiryField:             expiryField,
		NonceField:              nonceField,
		ExpectedOrderCommitment: orderCommitment,
		ExpectedOrderNullifier:  orderNullifier,
	}, nil
}

// OrderOwnerFieldForV1 maps an opaque owner string into a BN254 scalar field
// element outside the circuit (mirrors SecretFieldForV1). Owner is bound into
// both orderCommitment and orderNullifier, so it cannot be swapped.
func OrderOwnerFieldForV1(owner string) (*big.Int, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, fmt.Errorf("order owner is empty")
	}
	digest := sha256.Sum256([]byte(OrderOwnerFieldDomainTagV1 + "|" + owner))
	return bytesToBN254FieldBigInt(digest[:]), nil
}

// OrderMarketFieldForV1 maps an opaque market string into a BN254 field element.
func OrderMarketFieldForV1(market string) (*big.Int, error) {
	market = strings.TrimSpace(market)
	if market == "" {
		return nil, fmt.Errorf("order market is empty")
	}
	digest := sha256.Sum256([]byte(OrderMarketFieldDomainTagV1 + "|" + market))
	return bytesToBN254FieldBigInt(digest[:]), nil
}

// orderSideFieldV1 maps the order side to a small field element: buy=0, sell=1.
func orderSideFieldV1(side string) (*big.Int, error) {
	switch strings.ToLower(strings.TrimSpace(side)) {
	case "buy":
		return big.NewInt(0), nil
	case "sell":
		return big.NewInt(1), nil
	default:
		return nil, fmt.Errorf("order side %q invalid (want buy|sell)", side)
	}
}

func parseNonNegativeOrderField(value string, name string) (*big.Int, error) {
	out, err := parseNonNegativeDecimalForNullifier(value)
	if err != nil {
		return nil, fmt.Errorf("order %s %q invalid: %v", name, value, err)
	}
	return out, nil
}

// OrderCommitmentCircuitV1ForFields computes the field-native order commitment.
// It MUST match the circuit expression:
//
//	MiMC(ownerField, marketField, sideField, priceField, qtyField, expiryField, nonceField)
func OrderCommitmentCircuitV1ForFields(
	ownerField, marketField, sideField, priceField, qtyField, expiryField, nonceField *big.Int,
) (*big.Int, error) {
	fields := []*big.Int{ownerField, marketField, sideField, priceField, qtyField, expiryField, nonceField}
	h := bn254mimc.NewMiMC()
	for i, f := range fields {
		if f == nil {
			return nil, fmt.Errorf("order field[%d] is nil", i)
		}
		if f.Sign() < 0 {
			return nil, fmt.Errorf("order field[%d] must be non-negative", i)
		}
		if _, err := h.Write(bigIntToBN254FieldBytes(f)); err != nil {
			return nil, fmt.Errorf("write order field[%d]: %w", i, err)
		}
	}
	return bytesToBN254FieldBigInt(h.Sum(nil)), nil
}

// OrderNullifierCircuitV1ForFields computes the field-native order nullifier. It
// MUST match the circuit expression: MiMC(ownerField, orderCommitment).
func OrderNullifierCircuitV1ForFields(ownerField, orderCommitment *big.Int) (*big.Int, error) {
	if ownerField == nil || orderCommitment == nil {
		return nil, fmt.Errorf("ownerField/orderCommitment is nil")
	}
	h := bn254mimc.NewMiMC()
	if _, err := h.Write(bigIntToBN254FieldBytes(ownerField)); err != nil {
		return nil, fmt.Errorf("write owner field: %w", err)
	}
	if _, err := h.Write(bigIntToBN254FieldBytes(orderCommitment)); err != nil {
		return nil, fmt.Errorf("write order commitment: %w", err)
	}
	return bytesToBN254FieldBigInt(h.Sum(nil)), nil
}

// OrderCommitmentCircuitV1Hex returns the 0x-prefixed field-native order
// commitment for a canonical order.
func OrderCommitmentCircuitV1Hex(order OrderFieldsV1) (string, error) {
	input, err := BuildOrderHashBindingCircuitV1Input(order)
	if err != nil {
		return "", err
	}
	return "0x" + fieldBigIntToHex(input.ExpectedOrderCommitment), nil
}

// OrderNullifierCircuitV1Hex returns the 0x-prefixed field-native order nullifier.
func OrderNullifierCircuitV1Hex(order OrderFieldsV1) (string, error) {
	input, err := BuildOrderHashBindingCircuitV1Input(order)
	if err != nil {
		return "", err
	}
	return "0x" + fieldBigIntToHex(input.ExpectedOrderNullifier), nil
}

func compileAndSetupOrderCircuit() (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	var circuit OrderHashBindingCircuitV1
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile order hash binding circuit v1: %w", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup order hash binding circuit v1: %w", err)
	}
	return ccs, provingKey, verifyingKey, nil
}

func orderAssignment(input OrderHashBindingCircuitV1Input) OrderHashBindingCircuitV1 {
	return OrderHashBindingCircuitV1{
		OwnerField:              input.OwnerField,
		MarketField:             input.MarketField,
		SideField:               input.SideField,
		PriceField:              input.PriceField,
		QtyField:                input.QtyField,
		ExpiryField:             input.ExpiryField,
		NonceField:              input.NonceField,
		ExpectedOrderCommitment: input.ExpectedOrderCommitment,
		ExpectedOrderNullifier:  input.ExpectedOrderNullifier,
	}
}

// ProveOrderHashBindingCircuitV1 compiles+sets up the circuit, proves the order
// binding, and returns the 0x-prefixed proof. It fails if the witness does not
// satisfy the constraints (e.g. tampered/forged commitment or owner).
func ProveOrderHashBindingCircuitV1(input OrderHashBindingCircuitV1Input) (string, error) {
	ccs, provingKey, _, err := compileAndSetupOrderCircuit()
	if err != nil {
		return "", err
	}

	assignment := orderAssignment(input)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("build order hash binding witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove order hash binding circuit v1: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize order hash binding proof: %w", err)
	}
	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}

// ProveAndVerifyOrderHashBindingCircuitV1 proves and then verifies against the
// PUBLIC commitments, returning the proof hex. If publicInputs differ from what
// the private witness produces (a forged/tampered public claim), prove fails;
// verify is the second guard for a valid proof presented against wrong public
// inputs. Used by tests to exercise both DoD paths.
func ProveAndVerifyOrderHashBindingCircuitV1(
	witnessInput OrderHashBindingCircuitV1Input,
	publicCommitment *big.Int,
	publicNullifier *big.Int,
) error {
	ccs, provingKey, verifyingKey, err := compileAndSetupOrderCircuit()
	if err != nil {
		return err
	}

	assignment := orderAssignment(witnessInput)
	fullWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("build order hash binding witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, provingKey, fullWitness)
	if err != nil {
		return fmt.Errorf("prove order hash binding circuit v1: %w", err)
	}

	publicAssignment := OrderHashBindingCircuitV1{
		ExpectedOrderCommitment: publicCommitment,
		ExpectedOrderNullifier:  publicNullifier,
	}
	publicWitness, err := frontend.NewWitness(&publicAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("build public witness: %w", err)
	}

	if err := groth16.Verify(proof, verifyingKey, publicWitness); err != nil {
		return fmt.Errorf("verify order hash binding circuit v1: %w", err)
	}
	return nil
}
