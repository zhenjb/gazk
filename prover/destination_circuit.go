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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdmimc "github.com/consensys/gnark/std/hash/mimc"
)

// DestinationHashCircuitV1 is the D4-A field-native destination hash prototype.
//
// It proves:
//
//	expectedDestinationHash = MiMC(destinationField)
//
// This is intentionally NOT wired into /prove yet.
//
// Important:
// - destination string hashing is not done inside the circuit.
// - service/preprocessing maps destination -> destinationField.
// - D4-B can later wire this into the main v1 settlement circuit.
type DestinationHashCircuitV1 struct {
	DestinationField        frontend.Variable
	ExpectedDestinationHash frontend.Variable `gnark:",public"`
}

func (c *DestinationHashCircuitV1) Define(api frontend.API) error {
	hasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}

	hasher.Write(c.DestinationField)
	computed := hasher.Sum()

	api.AssertIsEqual(computed, c.ExpectedDestinationHash)
	return nil
}

type DestinationHashCircuitV1Input struct {
	DestinationField        *big.Int
	ExpectedDestinationHash *big.Int
}

func BuildDestinationHashCircuitV1Input(destination string) (DestinationHashCircuitV1Input, error) {
	destinationField, err := DestinationFieldForV1(destination)
	if err != nil {
		return DestinationHashCircuitV1Input{}, err
	}

	expectedDestinationHash, err := DestinationHashCircuitV1ForField(destinationField)
	if err != nil {
		return DestinationHashCircuitV1Input{}, err
	}

	return DestinationHashCircuitV1Input{
		DestinationField:        destinationField,
		ExpectedDestinationHash: expectedDestinationHash,
	}, nil
}

// DestinationFieldForV1 maps an opaque destination string into a BN254 scalar
// field element outside the circuit.
//
// This is a preprocessing helper for D4-A. It deliberately keeps arbitrary
// string handling outside the circuit.
func DestinationFieldForV1(destination string) (*big.Int, error) {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return nil, fmt.Errorf("destination is empty")
	}

	digest := sha256.Sum256([]byte("zkdex/destinationField/v1|" + destination))
	return bytesToBN254FieldBigInt(digest[:]), nil
}

// DestinationHashCircuitV1ForField computes the native-field destination hash
// used by DestinationHashCircuitV1.
//
// It must match the circuit expression:
//
//	MiMC(destinationField)
func DestinationHashCircuitV1ForField(destinationField *big.Int) (*big.Int, error) {
	if destinationField == nil {
		return nil, fmt.Errorf("destinationField is nil")
	}

	if destinationField.Sign() < 0 {
		return nil, fmt.Errorf("destinationField must be non-negative")
	}

	h := bn254mimc.NewMiMC()
	if _, err := h.Write(bigIntToBN254FieldBytes(destinationField)); err != nil {
		return nil, fmt.Errorf("write destination field: %w", err)
	}

	return bytesToBN254FieldBigInt(h.Sum(nil)), nil
}

func DestinationHashCircuitV1Hex(destination string) (string, error) {
	input, err := BuildDestinationHashCircuitV1Input(destination)
	if err != nil {
		return "", err
	}

	return "0x" + fieldBigIntToHex(input.ExpectedDestinationHash), nil
}

func ProveDestinationHashCircuitV1(input DestinationHashCircuitV1Input) (string, error) {
	var circuit DestinationHashCircuitV1

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return "", fmt.Errorf("compile destination hash circuit v1: %w", err)
	}

	provingKey, _, err := groth16.Setup(ccs)
	if err != nil {
		return "", fmt.Errorf("setup destination hash circuit v1: %w", err)
	}

	assignment := DestinationHashCircuitV1{
		DestinationField:        input.DestinationField,
		ExpectedDestinationHash: input.ExpectedDestinationHash,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("build destination hash circuit v1 witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove destination hash circuit v1: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize destination hash circuit v1 proof: %w", err)
	}

	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}
