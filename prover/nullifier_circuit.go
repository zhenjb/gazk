package prover

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdmimc "github.com/consensys/gnark/std/hash/mimc"
)

// NullifierCircuitV1 is the D3-A field-native nullifier prototype.
//
// It proves:
//
//	expectedNullifier = MiMC(secretField, nonceField)
//
// This is intentionally NOT wired into /prove yet.
//
// Important:
// - userSecret is not hashed inside the circuit in this prototype.
// - service/preprocessing maps userSecret -> secretField.
// - this avoids SHA-256 string hashing inside the circuit.
// - D3-B can later wire this into the main proof path for GAZK_HASH_MODE=v1-mimc.
type NullifierCircuitV1 struct {
	SecretField       frontend.Variable
	NonceField        frontend.Variable
	ExpectedNullifier frontend.Variable `gnark:",public"`
}

func (c *NullifierCircuitV1) Define(api frontend.API) error {
	hasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}

	hasher.Write(c.SecretField, c.NonceField)
	computed := hasher.Sum()

	api.AssertIsEqual(computed, c.ExpectedNullifier)
	return nil
}

type NullifierCircuitV1Input struct {
	SecretField       *big.Int
	NonceField        *big.Int
	ExpectedNullifier *big.Int
}

func BuildNullifierCircuitV1Input(userSecret string, nonce string) (NullifierCircuitV1Input, error) {
	secretField, err := SecretFieldForV1(userSecret)
	if err != nil {
		return NullifierCircuitV1Input{}, err
	}

	nonceField, err := parseNonNegativeDecimalForNullifier(nonce)
	if err != nil {
		return NullifierCircuitV1Input{}, fmt.Errorf("nonce %q invalid: %v", nonce, err)
	}

	expectedNullifier, err := NullifierCircuitV1ForFields(secretField, nonceField)
	if err != nil {
		return NullifierCircuitV1Input{}, err
	}

	return NullifierCircuitV1Input{
		SecretField:       secretField,
		NonceField:        nonceField,
		ExpectedNullifier: expectedNullifier,
	}, nil
}

// SecretFieldForV1 maps an opaque userSecret string into a BN254 scalar field
// element outside the circuit.
//
// This is a preprocessing helper for D3-A. It deliberately keeps arbitrary
// string handling outside the circuit.
func SecretFieldForV1(userSecret string) (*big.Int, error) {
	userSecret = strings.TrimSpace(userSecret)
	if userSecret == "" {
		return nil, fmt.Errorf("userSecret is empty")
	}

	digest := sha256.Sum256([]byte("zkdex/secretField/v1|" + userSecret))
	return bytesToBN254FieldBigInt(digest[:]), nil
}

// NullifierCircuitV1ForFields computes the native-field nullifier used by
// NullifierCircuitV1.
//
// It must match the circuit expression:
//
//	MiMC(secretField, nonceField)
func NullifierCircuitV1ForFields(secretField *big.Int, nonceField *big.Int) (*big.Int, error) {
	if secretField == nil {
		return nil, fmt.Errorf("secretField is nil")
	}

	if nonceField == nil {
		return nil, fmt.Errorf("nonceField is nil")
	}

	if secretField.Sign() < 0 {
		return nil, fmt.Errorf("secretField must be non-negative")
	}

	if nonceField.Sign() < 0 {
		return nil, fmt.Errorf("nonceField must be non-negative")
	}

	h := bn254mimc.NewMiMC()

	if _, err := h.Write(bigIntToBN254FieldBytes(secretField)); err != nil {
		return nil, fmt.Errorf("write secret field: %w", err)
	}

	if _, err := h.Write(bigIntToBN254FieldBytes(nonceField)); err != nil {
		return nil, fmt.Errorf("write nonce field: %w", err)
	}

	return bytesToBN254FieldBigInt(h.Sum(nil)), nil
}

func NullifierCircuitV1Hex(userSecret string, nonce string) (string, error) {
	input, err := BuildNullifierCircuitV1Input(userSecret, nonce)
	if err != nil {
		return "", err
	}

	return "0x" + fieldBigIntToHex(input.ExpectedNullifier), nil
}

func ProveNullifierCircuitV1(input NullifierCircuitV1Input) (string, error) {
	var circuit NullifierCircuitV1

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return "", fmt.Errorf("compile nullifier circuit v1: %w", err)
	}

	provingKey, _, err := groth16.Setup(ccs)
	if err != nil {
		return "", fmt.Errorf("setup nullifier circuit v1: %w", err)
	}

	assignment := NullifierCircuitV1{
		SecretField:       input.SecretField,
		NonceField:        input.NonceField,
		ExpectedNullifier: input.ExpectedNullifier,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("build nullifier circuit v1 witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove nullifier circuit v1: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize nullifier circuit v1 proof: %w", err)
	}

	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}

func bigIntToBN254FieldBytes(value *big.Int) []byte {
	var element bn254fr.Element
	element.SetBigInt(value)

	encoded := element.Bytes()
	return encoded[:]
}

func bytesToBN254FieldBigInt(raw []byte) *big.Int {
	var element bn254fr.Element
	element.SetBigInt(new(big.Int).SetBytes(raw))

	return element.BigInt(new(big.Int))
}

func fieldBigIntToHex(value *big.Int) string {
	return hex.EncodeToString(bigIntToBN254FieldBytes(value))
}
