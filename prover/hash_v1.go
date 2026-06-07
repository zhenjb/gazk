package prover

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

const (
	NullifierDomainTagV1       = "zkdex/nullifier/v1"
	DestinationHashDomainTagV1 = "zkdex/withdrawAddr/v1"
	HashV1ID                   = "bn254-mimc-v1"
)

// NullifierForV1 derives the future circuit-friendly nullifier.
//
// This does NOT replace the current v0 SHA-256 path yet.
// Current /prove still validates v0 for compatibility with ganc-sys.
//
// Transitional v1 contract:
//
//	canonicalPayload = "zkdex/nullifier/v1|userSecret|canonicalNonce"
//	fieldInput       = Field(SHA256(canonicalPayload))
//	nullifierV1      = MiMC_BN254(fieldInput)
//
// Nonce canonicalization matches v0:
//
//	"01" -> "1"
//
// Note: this helper locks deterministic v1 vectors for the next stage.
// The final circuit preimage design may later restrict userSecret/destination
// to field-native values to avoid byte hashing inside the circuit.
func NullifierForV1(userSecret string, nonce string) (string, error) {
	userSecret = strings.TrimSpace(userSecret)
	if userSecret == "" {
		return "", fmt.Errorf("userSecret is empty")
	}

	parsedNonce, err := parseNonNegativeDecimalForNullifier(nonce)
	if err != nil {
		return "", fmt.Errorf("nonce %q invalid: %v", nonce, err)
	}

	payload := NullifierDomainTagV1 + "|" + userSecret + "|" + parsedNonce.String()
	return mimcV1Hex(payload)
}

// DestinationHashForV1 derives the future circuit-friendly destination hash.
//
// This does NOT replace the current v0 SHA-256 path yet.
// Current /prove still validates v0 for compatibility with ganc-sys.
//
// Transitional v1 contract:
//
//	canonicalPayload  = "zkdex/withdrawAddr/v1|canonicalDestination"
//	fieldInput        = Field(SHA256(canonicalPayload))
//	destinationHashV1 = MiMC_BN254(fieldInput)
func DestinationHashForV1(destination string) (string, error) {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return "", fmt.Errorf("destination is empty")
	}

	payload := DestinationHashDomainTagV1 + "|" + destination
	return mimcV1Hex(payload)
}

func mimcV1Hex(payload string) (string, error) {
	fieldBytes := payloadToBN254FieldBytes(payload)

	h := bn254mimc.NewMiMC()
	if _, err := h.Write(fieldBytes); err != nil {
		return "", fmt.Errorf("write MiMC field input: %w", err)
	}

	return "0x" + hex.EncodeToString(h.Sum(nil)), nil
}

func payloadToBN254FieldBytes(payload string) []byte {
	digest := sha256.Sum256([]byte(payload))

	var fieldElement bn254fr.Element
	fieldElement.SetBigInt(new(big.Int).SetBytes(digest[:]))

	encoded := fieldElement.Bytes()
	return encoded[:]
}
