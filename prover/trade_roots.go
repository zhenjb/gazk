package prover

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	bn254mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

// ZK-T07 — tradesRoot / ordersRoot binding.
//
// Public inputs [6]=tradesRoot, [7]=ordersRoot must commit to the WHOLE
// trades[]/orders[] array so no fill/order can be altered after the proof is
// made. The circuit (trade_roots_circuit.go) recomputes both roots from the leaf
// fields and AssertIsEqual with [6]/[7]; tamper one field -> root changes ->
// verify fails.
//
// Pitfall (plan): leaf order + padding must match P3 ABSOLUTELY — the most common
// off-chain/circuit mismatch. This file pins BOTH:
//
//   - v0 (wire): OrdersRootV0/TradesRootV0 reproduce P3 state.trade_commitments
//     BYTE-EXACT (same domain tag, '|' field separators, ';' entry terminator,
//     order sort by (Sequence, OrderHash), fills in matching order). Locked to the
//     zk_trade_io.md §8 vector so gazk / P3 / chain agree on the wire root.
//
//   - v1 (in-circuit): OrdersRootV1Field/TradesRootV1Field fold the field-mapped
//     leaves with MiMC in the SAME leaf order — the value the circuit binds. The
//     v0 SHA-256 root and the v1 MiMC root reconcile at the lockstep migration
//     (zk_trade_io.md §10), exactly like the ZK-T06 nullifier.

const (
	OrdersRootDomainTagV0 = "zkdex/batch/ordersRoot/v0"
	TradesRootDomainTagV0 = "zkdex/batch/tradesRoot/v0"
	OrdersRootDomainTagV1 = "zkdex/batch/ordersRoot/v1"
	TradesRootDomainTagV1 = "zkdex/batch/tradesRoot/v1"

	leafFieldDomainTagV1 = "zkdex/leafField/v1"
)

// OrderLeaf is one order's post-batch state committed into ordersRoot (mirrors
// P3 state.OrderCommitmentInput). Side is "buy"/"sell"; Filled is a bool.
type OrderLeaf struct {
	OrderHash string
	Owner     string
	Side      string
	Price     string
	Qty       string
	Remaining string
	Filled    bool
	Sequence  uint64
}

// FillLeaf is one fill committed into tradesRoot (mirrors types.Fill fields).
type FillLeaf struct {
	TradeID        string
	Market         string
	MakerOrderHash string
	TakerOrderHash string
	Price          string
	Qty            string
	MakerFee       string
	TakerFee       string
	Buyer          string
	Seller         string
}

func sha256Hex0x(b []byte) string {
	sum := sha256.Sum256(b)
	return "0x" + hex.EncodeToString(sum[:])
}

// sortedOrders returns a copy sorted by (Sequence, OrderHash) — P3's fixed leaf
// order, independent of caller order.
func sortedOrders(orders []OrderLeaf) []OrderLeaf {
	out := make([]OrderLeaf, len(orders))
	copy(out, orders)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Sequence != out[j].Sequence {
			return out[i].Sequence < out[j].Sequence
		}
		return out[i].OrderHash < out[j].OrderHash
	})
	return out
}

// OrdersRootV0 reproduces P3 ordersRoot BYTE-EXACT (SHA-256 wire value),
// including the duplicate-nullifier guard.
func OrdersRootV0(orders []OrderLeaf) (string, error) {
	sorted := sortedOrders(orders)
	seen := make(map[string]struct{}, len(sorted))

	var b strings.Builder
	b.WriteString(OrdersRootDomainTagV0)
	b.WriteByte('|')
	for _, o := range sorted {
		nullifier, err := OrderNullifierV0(o.Owner, o.OrderHash)
		if err != nil {
			return "", err
		}
		if _, dup := seen[nullifier]; dup {
			return "", fmt.Errorf("duplicate order nullifier in batch: %s", nullifier)
		}
		seen[nullifier] = struct{}{}

		b.WriteString(o.OrderHash)
		b.WriteByte('|')
		b.WriteString(strings.TrimSpace(o.Owner))
		b.WriteByte('|')
		b.WriteString(nullifier)
		b.WriteByte('|')
		b.WriteString(o.Side)
		b.WriteByte('|')
		b.WriteString(o.Price)
		b.WriteByte('|')
		b.WriteString(o.Qty)
		b.WriteByte('|')
		b.WriteString(o.Remaining)
		b.WriteByte('|')
		b.WriteString(strconv.FormatBool(o.Filled))
		b.WriteByte(';')
	}
	return sha256Hex0x([]byte(b.String())), nil
}

// TradesRootV0 reproduces P3 tradesRoot BYTE-EXACT, fills in the given matching
// order (never reordered).
func TradesRootV0(fills []FillLeaf) string {
	var b strings.Builder
	b.WriteString(TradesRootDomainTagV0)
	b.WriteByte('|')
	for _, f := range fills {
		b.WriteString(f.TradeID)
		b.WriteByte('|')
		b.WriteString(f.Market)
		b.WriteByte('|')
		b.WriteString(f.MakerOrderHash)
		b.WriteByte('|')
		b.WriteString(f.TakerOrderHash)
		b.WriteByte('|')
		b.WriteString(f.Price)
		b.WriteByte('|')
		b.WriteString(f.Qty)
		b.WriteByte('|')
		b.WriteString(f.MakerFee)
		b.WriteByte('|')
		b.WriteString(f.TakerFee)
		b.WriteByte('|')
		b.WriteString(f.Buyer)
		b.WriteByte('|')
		b.WriteString(f.Seller)
		b.WriteByte(';')
	}
	return sha256Hex0x([]byte(b.String()))
}

// EmptyOrdersRootV0 / EmptyTradesRootV0 are the empty-batch sentinels [6]/[7]
// carry when a batch has no trades (matches P3 EmptyOrdersRoot/EmptyTradesRoot).
func EmptyOrdersRootV0() string {
	root, _ := OrdersRootV0(nil)
	return root
}

func EmptyTradesRootV0() string {
	return TradesRootV0(nil)
}

// ---------------------------------------------------------------------------
// v1 field-native roots (what the circuit binds).
// ---------------------------------------------------------------------------

// fieldForLeafStringV1 maps a canonical leaf string to a BN254 field element.
// Every leaf field (hex, string, decimal, bool) is mapped uniformly so the v1
// root commits to the same logical values as the v0 root.
func fieldForLeafStringV1(s string) *big.Int {
	digest := sha256.Sum256([]byte(leafFieldDomainTagV1 + "|" + s))
	return bytesToBN254FieldBigInt(digest[:])
}

// orderLeafFieldsV1 maps an order to its 8 leaf field elements, in the SAME order
// as the v0 leaf. Nullifier is derived from (owner, orderHash) — callers cannot
// supply an inconsistent value.
func orderLeafFieldsV1(o OrderLeaf) ([]*big.Int, error) {
	nullifier, err := OrderNullifierV0(o.Owner, o.OrderHash)
	if err != nil {
		return nil, err
	}
	return []*big.Int{
		fieldForLeafStringV1(o.OrderHash),
		fieldForLeafStringV1(strings.TrimSpace(o.Owner)),
		fieldForLeafStringV1(nullifier),
		fieldForLeafStringV1(o.Side),
		fieldForLeafStringV1(o.Price),
		fieldForLeafStringV1(o.Qty),
		fieldForLeafStringV1(o.Remaining),
		fieldForLeafStringV1(strconv.FormatBool(o.Filled)),
	}, nil
}

// fillLeafFieldsV1 maps a fill to its 10 leaf field elements, in v0 leaf order.
func fillLeafFieldsV1(f FillLeaf) []*big.Int {
	return []*big.Int{
		fieldForLeafStringV1(f.TradeID),
		fieldForLeafStringV1(f.Market),
		fieldForLeafStringV1(f.MakerOrderHash),
		fieldForLeafStringV1(f.TakerOrderHash),
		fieldForLeafStringV1(f.Price),
		fieldForLeafStringV1(f.Qty),
		fieldForLeafStringV1(f.MakerFee),
		fieldForLeafStringV1(f.TakerFee),
		fieldForLeafStringV1(f.Buyer),
		fieldForLeafStringV1(f.Seller),
	}
}

// mimcFold absorbs the domain field then every leaf field in order — the exact
// sequence the circuit's stdmimc hasher absorbs, so the roots match.
func mimcFold(domainTag string, leafFields []*big.Int) *big.Int {
	h := bn254mimc.NewMiMC()
	_, _ = h.Write(bigIntToBN254FieldBytes(fieldForLeafStringV1(domainTag)))
	for _, f := range leafFields {
		_, _ = h.Write(bigIntToBN254FieldBytes(f))
	}
	return bytesToBN254FieldBigInt(h.Sum(nil))
}

// OrdersRootV1Field folds the field-mapped order leaves (sorted like P3) with
// MiMC. Returns the field element and its 0x hex.
func OrdersRootV1Field(orders []OrderLeaf) (*big.Int, string, error) {
	sorted := sortedOrders(orders)
	all := make([]*big.Int, 0, len(sorted)*8)
	for _, o := range sorted {
		fields, err := orderLeafFieldsV1(o)
		if err != nil {
			return nil, "", err
		}
		all = append(all, fields...)
	}
	root := mimcFold(OrdersRootDomainTagV1, all)
	return root, "0x" + fieldBigIntToHex(root), nil
}

// TradesRootV1Field folds the field-mapped fill leaves (matching order) with MiMC.
func TradesRootV1Field(fills []FillLeaf) (*big.Int, string) {
	all := make([]*big.Int, 0, len(fills)*10)
	for _, f := range fills {
		all = append(all, fillLeafFieldsV1(f)...)
	}
	root := mimcFold(TradesRootDomainTagV1, all)
	return root, "0x" + fieldBigIntToHex(root)
}
