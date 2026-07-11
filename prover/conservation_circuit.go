package prover

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// ZK-T05 — Conservation + non-negative constraint ("no money printing").
//
// This proves each fill neither creates nor destroys value and drives no balance
// negative after apply. Without it a wrong matching could mint or burn value and
// the proof would still pass. It mirrors STATE-T06 (state/trade_apply.go) EXACTLY.
//
// Per fill (all integers in smallest units; price is fixed-point):
//
//	notional derivation (baseQty * price = quoteQty):
//	    QuoteNotional * ScaleFactor == PriceMantissa * BaseQty
//	    (ScaleFactor = 10^priceScale; qty is whole settlement units)
//
//	role fees (maker pays makerFee, taker pays takerFee):
//	    buyerFee  = BuyerIsMaker ? MakerFee : TakerFee
//	    sellerFee = BuyerIsMaker ? TakerFee : MakerFee
//
//	balance deltas (the ACTUAL deltas P3 applied, carried as witness):
//	    BuyerQuoteOut == QuoteNotional + buyerFee     (buyer reserved quote spent)
//	    SellerQuoteIn == QuoteNotional - sellerFee     (seller available quote gained)
//	    FeeCredited   == MakerFee + TakerFee           (fee account gained)
//	    BuyerBaseIn   == BaseQty                        (buyer available base gained)
//	    SellerBaseOut == BaseQty                        (seller reserved base spent)
//
//	CONSERVATION (Σ delta = 0 per denom, fee inside the sum):
//	    quote: BuyerQuoteOut == SellerQuoteIn + FeeCredited   (in = out + fee)
//	    base:  SellerBaseOut == BuyerBaseIn
//
//	NON-NEGATIVE after apply (bit-decomposition range checks — reserved AND the
//	credited amounts, per plan "don't forget reserved"):
//	    sellerFee     <= QuoteNotional                 (SellerQuoteIn >= 0)
//	    BuyerQuoteOut <= BuyerReservedQuoteBefore       (buyer reserved covers spend)
//	    SellerBaseOut <= SellerReservedBaseBefore        (seller reserved covers spend)
//
// Fee rounding note (plan pitfall): fees are FLOOR in P3 (floorFeeUnits). This
// circuit takes the already-floored MakerFee/TakerFee as witness and checks the
// deltas are consistent with them; the floor derivation from bps is bound to the
// fill at ZK-T07 (fill fields -> tradesRoot). So a wrong/rounded fee shows up as
// an inconsistent delta here (BuyerQuoteOut / SellerQuoteIn / FeeCredited fail).
//
// Prototype: single fill, all witness private, NOT wired into /prove yet. ZK-T07
// binds these amounts into tradesRoot; ZK-T09 assembles the unified circuit and
// generalizes Σ delta = 0 across all fills in the batch.
type ConservationCircuitV1 struct {
	// Fixed-point notional inputs.
	PriceMantissa frontend.Variable
	ScaleFactor   frontend.Variable
	BaseQty       frontend.Variable
	QuoteNotional frontend.Variable

	// Role fees (already floored, in quote units).
	MakerFee     frontend.Variable
	TakerFee     frontend.Variable
	BuyerIsMaker frontend.Variable // boolean

	// Actual balance deltas applied by P3.
	BuyerQuoteOut frontend.Variable
	SellerQuoteIn frontend.Variable
	FeeCredited   frontend.Variable
	BuyerBaseIn   frontend.Variable
	SellerBaseOut frontend.Variable

	// Reserved balances before apply (for non-negativity).
	BuyerReservedQuoteBefore frontend.Variable
	SellerReservedBaseBefore frontend.Variable
}

// AmountRangeBits bounds each amount. 100 bits holds realistic token amounts
// (up to ~1.3e30, ample even for 18-decimal tokens) while keeping every product
// of two amounts <= 200 bits, safely below the BN254 field (~254 bits) so
// multiplications and comparisons never wrap.
const AmountRangeBits = 100

func (c *ConservationCircuitV1) Define(api frontend.API) error {
	api.AssertIsBoolean(c.BuyerIsMaker)

	// Range-check every amount (no field wraparound in products/compares).
	for _, v := range []frontend.Variable{
		c.PriceMantissa, c.ScaleFactor, c.BaseQty, c.QuoteNotional,
		c.MakerFee, c.TakerFee,
		c.BuyerQuoteOut, c.SellerQuoteIn, c.FeeCredited, c.BuyerBaseIn, c.SellerBaseOut,
		c.BuyerReservedQuoteBefore, c.SellerReservedBaseBefore,
	} {
		api.ToBinary(v, AmountRangeBits)
	}

	// 1. Notional / fixed-point identity: baseQty * price = quoteQty.
	api.AssertIsEqual(
		api.Mul(c.QuoteNotional, c.ScaleFactor),
		api.Mul(c.PriceMantissa, c.BaseQty),
	)

	// 2. Role fee assignment.
	buyerFee := api.Select(c.BuyerIsMaker, c.MakerFee, c.TakerFee)
	sellerFee := api.Select(c.BuyerIsMaker, c.TakerFee, c.MakerFee)

	// 3. Deltas consistent with notional + fees.
	api.AssertIsEqual(c.BuyerQuoteOut, api.Add(c.QuoteNotional, buyerFee))
	api.AssertIsLessOrEqual(sellerFee, c.QuoteNotional) // SellerQuoteIn >= 0
	api.AssertIsEqual(c.SellerQuoteIn, api.Sub(c.QuoteNotional, sellerFee))
	api.AssertIsEqual(c.FeeCredited, api.Add(c.MakerFee, c.TakerFee))
	api.AssertIsEqual(c.BuyerBaseIn, c.BaseQty)
	api.AssertIsEqual(c.SellerBaseOut, c.BaseQty)

	// 4. Conservation per denom (Σ delta = 0, fee inside the sum).
	api.AssertIsEqual(c.BuyerQuoteOut, api.Add(c.SellerQuoteIn, c.FeeCredited)) // in = out + fee
	api.AssertIsEqual(c.SellerBaseOut, c.BuyerBaseIn)

	// 5. Non-negative after apply: reserved must cover each spend.
	api.AssertIsLessOrEqual(c.BuyerQuoteOut, c.BuyerReservedQuoteBefore)
	api.AssertIsLessOrEqual(c.SellerBaseOut, c.SellerReservedBaseBefore)

	return nil
}

type ConservationCircuitV1Input struct {
	PriceMantissa *big.Int
	ScaleFactor   *big.Int
	BaseQty       *big.Int
	QuoteNotional *big.Int

	MakerFee     *big.Int
	TakerFee     *big.Int
	BuyerIsMaker *big.Int

	BuyerQuoteOut *big.Int
	SellerQuoteIn *big.Int
	FeeCredited   *big.Int
	BuyerBaseIn   *big.Int
	SellerBaseOut *big.Int

	BuyerReservedQuoteBefore *big.Int
	SellerReservedBaseBefore *big.Int
}

// ConservationFill is the economics of one fill in string form.
type ConservationFill struct {
	Price                    string // decimal, e.g. "100" or "0.5"
	Qty                      string // whole settlement units (base)
	MakerFee                 string // integer quote units (already floored)
	TakerFee                 string // integer quote units (already floored)
	BuyerIsMaker             bool
	BuyerReservedQuoteBefore string // integer quote units
	SellerReservedBaseBefore string // integer base units
}

// BuildConservationCircuitV1Input computes the HONEST witness (the deltas P3
// would apply) from a fill's economics. Tests tamper the returned struct to build
// non-conserving / over-reserve / bad-fee vectors.
func BuildConservationCircuitV1Input(f ConservationFill) (ConservationCircuitV1Input, error) {
	priceMant, priceScale, err := parseNonNegativeDecimalParts(f.Price)
	if err != nil {
		return ConservationCircuitV1Input{}, fmt.Errorf("price %q: %w", f.Price, err)
	}
	qtyInt, err := parseWholeAmount(f.Qty, "qty")
	if err != nil {
		return ConservationCircuitV1Input{}, err
	}
	makerFee, err := parseWholeAmount(f.MakerFee, "makerFee")
	if err != nil {
		return ConservationCircuitV1Input{}, err
	}
	takerFee, err := parseWholeAmount(f.TakerFee, "takerFee")
	if err != nil {
		return ConservationCircuitV1Input{}, err
	}
	buyerReserved, err := parseWholeAmount(f.BuyerReservedQuoteBefore, "buyerReservedQuoteBefore")
	if err != nil {
		return ConservationCircuitV1Input{}, err
	}
	sellerReserved, err := parseWholeAmount(f.SellerReservedBaseBefore, "sellerReservedBaseBefore")
	if err != nil {
		return ConservationCircuitV1Input{}, err
	}

	// notional = price * qty (whole quote units), exact fixed point like P3
	// mulDecimal(price, qty).toIntExact(): notional = priceMant*qty / 10^priceScale.
	scaleFactor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(priceScale)), nil)
	num := new(big.Int).Mul(priceMant, qtyInt)
	notional := new(big.Int)
	rem := new(big.Int)
	notional.DivMod(num, scaleFactor, rem)
	if rem.Sign() != 0 {
		return ConservationCircuitV1Input{}, fmt.Errorf("notional price*qty (%s*%s) not whole units", f.Price, f.Qty)
	}

	buyerFee, sellerFee := takerFee, makerFee
	if f.BuyerIsMaker {
		buyerFee, sellerFee = makerFee, takerFee
	}
	if sellerFee.Cmp(notional) > 0 {
		return ConservationCircuitV1Input{}, fmt.Errorf("seller fee %s exceeds notional %s", sellerFee, notional)
	}

	buyerQuoteOut := new(big.Int).Add(notional, buyerFee)
	sellerQuoteIn := new(big.Int).Sub(notional, sellerFee)
	feeCredited := new(big.Int).Add(makerFee, takerFee)

	makerBit := big.NewInt(0)
	if f.BuyerIsMaker {
		makerBit = big.NewInt(1)
	}

	return ConservationCircuitV1Input{
		PriceMantissa:            priceMant,
		ScaleFactor:              scaleFactor,
		BaseQty:                  qtyInt,
		QuoteNotional:            notional,
		MakerFee:                 makerFee,
		TakerFee:                 takerFee,
		BuyerIsMaker:             makerBit,
		BuyerQuoteOut:            buyerQuoteOut,
		SellerQuoteIn:            sellerQuoteIn,
		FeeCredited:              feeCredited,
		BuyerBaseIn:              new(big.Int).Set(qtyInt),
		SellerBaseOut:            new(big.Int).Set(qtyInt),
		BuyerReservedQuoteBefore: buyerReserved,
		SellerReservedBaseBefore: sellerReserved,
	}, nil
}

// parseWholeAmount parses a non-negative whole-integer decimal string.
func parseWholeAmount(s string, name string) (*big.Int, error) {
	mant, scale, err := parseNonNegativeDecimalParts(s)
	if err != nil {
		return nil, fmt.Errorf("%s %q: %w", name, s, err)
	}
	if scale != 0 {
		return nil, fmt.Errorf("%s %q must be whole units", name, s)
	}
	return mant, nil
}

func conservationAssignment(in ConservationCircuitV1Input) ConservationCircuitV1 {
	return ConservationCircuitV1{
		PriceMantissa:            in.PriceMantissa,
		ScaleFactor:              in.ScaleFactor,
		BaseQty:                  in.BaseQty,
		QuoteNotional:            in.QuoteNotional,
		MakerFee:                 in.MakerFee,
		TakerFee:                 in.TakerFee,
		BuyerIsMaker:             in.BuyerIsMaker,
		BuyerQuoteOut:            in.BuyerQuoteOut,
		SellerQuoteIn:            in.SellerQuoteIn,
		FeeCredited:              in.FeeCredited,
		BuyerBaseIn:              in.BuyerBaseIn,
		SellerBaseOut:            in.SellerBaseOut,
		BuyerReservedQuoteBefore: in.BuyerReservedQuoteBefore,
		SellerReservedBaseBefore: in.SellerReservedBaseBefore,
	}
}

func compileAndSetupConservationCircuit() (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	var circuit ConservationCircuitV1
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile conservation circuit v1: %w", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup conservation circuit v1: %w", err)
	}
	return ccs, provingKey, verifyingKey, nil
}

// ProveConservationCircuitV1 compiles+sets up and proves the fill conserves value
// and drives no balance negative. It fails if any invariant is violated
// (non-conserving deltas, insufficient reserved, or bad fee).
func ProveConservationCircuitV1(input ConservationCircuitV1Input) (string, error) {
	ccs, provingKey, _, err := compileAndSetupConservationCircuit()
	if err != nil {
		return "", err
	}

	assignment := conservationAssignment(input)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("build conservation witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove conservation circuit v1: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize conservation proof: %w", err)
	}
	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}
