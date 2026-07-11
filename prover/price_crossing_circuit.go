package prover

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// ZK-T04 — Price-crossing constraint.
//
// The off-chain matching engine is the minimally-trusted party: the chain does
// not run matching. This circuit proves every fill obeys the price rules so the
// operator cannot cross orders at a wrong price to a user's loss:
//
//	ask <= bid                       (crossing: highest bid reaches lowest ask)
//	fillPrice == makerPrice          (determinism: trade price is the resting/maker order price)
//	ask <= fillPrice <= bid          (both parties' limits: buyer pays <= bid, seller gets >= ask)
//
// makerPrice = MakerIsBid ? bidPrice : askPrice, matching STATE-T05 exactly (the
// maker is the order that rested first — smaller sequence).
//
// Scale (the ZK-T04 pitfall). P3 compares decimals by aligning both mantissas to
// the larger scale (state/decimal.go alignedMantissas) and comparing integers.
// This circuit does the SAME: the service maps bid/ask/fill to integers on a
// shared common scale = max(scale(bid), scale(ask), scale(fill)) before proving,
// so in-circuit integer comparison == P3 cmpDecimal EXACTLY. A scale mismatch
// here would fail the whole batch, so the mapping is pinned to P3's rule.
//
// Comparisons use bit-decomposition range-checks (PriceRangeBits) so the field
// cannot wrap around and make a large value look "less" than a small one.
//
// Prototype: single fill, all witness private, intentionally NOT wired into
// /prove yet (like the other ZK-T0x prototypes). ZK-T07 binds these prices into
// tradesRoot/ordersRoot; ZK-T09 assembles the unified trade circuit.
type PriceCrossingCircuitV1 struct {
	// Private, integers already mapped to the shared common scale.
	BidPrice   frontend.Variable
	AskPrice   frontend.Variable
	FillPrice  frontend.Variable
	MakerIsBid frontend.Variable // boolean: 1 if maker is the bid (buy) side
}

// PriceRangeBits bounds each scaled price integer. 128 bits comfortably holds
// realistic scaled prices while staying far below the BN254 field (~254 bits),
// so AssertIsLessOrEqual never wraps. Build-time guards reject inputs that do not
// fit. Revisit alongside the unified circuit (ZK-T09) if larger scales are used.
const PriceRangeBits = 128

func (c *PriceCrossingCircuitV1) Define(api frontend.API) error {
	// MakerIsBid must be a real boolean.
	api.AssertIsBoolean(c.MakerIsBid)

	// Range-check each price so comparisons are unambiguous (no field wraparound).
	api.ToBinary(c.BidPrice, PriceRangeBits)
	api.ToBinary(c.AskPrice, PriceRangeBits)
	api.ToBinary(c.FillPrice, PriceRangeBits)

	// Crossing: the lowest ask must be reachable by the highest bid.
	api.AssertIsLessOrEqual(c.AskPrice, c.BidPrice)

	// Determinism: the fill price is the maker's price.
	makerPrice := api.Select(c.MakerIsBid, c.BidPrice, c.AskPrice)
	api.AssertIsEqual(c.FillPrice, makerPrice)

	// Both parties' limits: seller receives >= ask, buyer pays <= bid. Combined
	// with fill == makerPrice and ask <= bid this pins the fill into [ask, bid].
	api.AssertIsLessOrEqual(c.AskPrice, c.FillPrice)
	api.AssertIsLessOrEqual(c.FillPrice, c.BidPrice)

	return nil
}

type PriceCrossingCircuitV1Input struct {
	BidPrice    *big.Int
	AskPrice    *big.Int
	FillPrice   *big.Int
	MakerIsBid  *big.Int // 0 or 1
	CommonScale int
}

// BuildPriceCrossingCircuitV1Input maps the three decimal price strings onto a
// shared common scale (max of their scales — P3's alignedMantissas rule) and
// returns the integer witness. makerIsBid selects which side's price is the fill
// price (STATE-T05 maker = earlier sequence).
func BuildPriceCrossingCircuitV1Input(bidPrice, askPrice, fillPrice string, makerIsBid bool) (PriceCrossingCircuitV1Input, error) {
	bidMant, bidScale, err := parseNonNegativeDecimalParts(bidPrice)
	if err != nil {
		return PriceCrossingCircuitV1Input{}, fmt.Errorf("bid price %q: %w", bidPrice, err)
	}
	askMant, askScale, err := parseNonNegativeDecimalParts(askPrice)
	if err != nil {
		return PriceCrossingCircuitV1Input{}, fmt.Errorf("ask price %q: %w", askPrice, err)
	}
	fillMant, fillScale, err := parseNonNegativeDecimalParts(fillPrice)
	if err != nil {
		return PriceCrossingCircuitV1Input{}, fmt.Errorf("fill price %q: %w", fillPrice, err)
	}

	common := bidScale
	if askScale > common {
		common = askScale
	}
	if fillScale > common {
		common = fillScale
	}

	bidInt := scaleMantissa(bidMant, common-bidScale)
	askInt := scaleMantissa(askMant, common-askScale)
	fillInt := scaleMantissa(fillMant, common-fillScale)

	for name, v := range map[string]*big.Int{"bid": bidInt, "ask": askInt, "fill": fillInt} {
		if v.BitLen() > PriceRangeBits {
			return PriceCrossingCircuitV1Input{}, fmt.Errorf("%s price does not fit in %d bits at common scale %d", name, PriceRangeBits, common)
		}
	}

	makerBit := big.NewInt(0)
	if makerIsBid {
		makerBit = big.NewInt(1)
	}

	return PriceCrossingCircuitV1Input{
		BidPrice:    bidInt,
		AskPrice:    askInt,
		FillPrice:   fillInt,
		MakerIsBid:  makerBit,
		CommonScale: common,
	}, nil
}

// scaleMantissa returns mant * 10^shift (shift >= 0).
func scaleMantissa(mant *big.Int, shift int) *big.Int {
	if shift == 0 {
		return new(big.Int).Set(mant)
	}
	factor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(shift)), nil)
	return new(big.Int).Mul(mant, factor)
}

// parseNonNegativeDecimalParts parses a non-negative decimal string into
// (mantissa, scale) EXACTLY like P3 state/decimal.go parseDecimal, so the scale
// alignment matches P3 bit-for-bit. Accepts "10", "10.5", "0.001", ".5"; rejects
// empty, signed, non-numeric, or multi-dot strings.
func parseNonNegativeDecimalParts(s string) (*big.Int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, 0, fmt.Errorf("empty decimal")
	}
	if strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") {
		return nil, 0, fmt.Errorf("sign not allowed")
	}

	intPart, fracPart := s, ""
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		intPart = s[:dot]
		fracPart = s[dot+1:]
		if strings.IndexByte(fracPart, '.') >= 0 {
			return nil, 0, fmt.Errorf("more than one dot")
		}
	}
	if intPart == "" {
		intPart = "0"
	}
	if !isAllDigitsLocal(intPart) || !isAllDigitsLocal(fracPart) {
		return nil, 0, fmt.Errorf("non-numeric")
	}

	mant, ok := new(big.Int).SetString(intPart+fracPart, 10)
	if !ok {
		return nil, 0, fmt.Errorf("invalid mantissa")
	}
	return mant, len(fracPart), nil
}

func isAllDigitsLocal(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func priceAssignment(input PriceCrossingCircuitV1Input) PriceCrossingCircuitV1 {
	return PriceCrossingCircuitV1{
		BidPrice:   input.BidPrice,
		AskPrice:   input.AskPrice,
		FillPrice:  input.FillPrice,
		MakerIsBid: input.MakerIsBid,
	}
}

func compileAndSetupPriceCircuit() (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	var circuit PriceCrossingCircuitV1
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile price crossing circuit v1: %w", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup price crossing circuit v1: %w", err)
	}
	return ccs, provingKey, verifyingKey, nil
}

// ProvePriceCrossingCircuitV1 compiles+sets up the circuit and proves the fill
// obeys the price rules. It fails if the witness violates any rule (non-crossing,
// wrong fill price, or fill outside [ask, bid]).
func ProvePriceCrossingCircuitV1(input PriceCrossingCircuitV1Input) (string, error) {
	ccs, provingKey, _, err := compileAndSetupPriceCircuit()
	if err != nil {
		return "", err
	}

	assignment := priceAssignment(input)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("build price crossing witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove price crossing circuit v1: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize price crossing proof: %w", err)
	}
	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}
