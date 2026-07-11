package contract

type SettlementDeposit struct {
	DepositID string `json:"depositId"`
	Owner     string `json:"owner"`
	Denom     string `json:"denom"`
	Amount    string `json:"amount"`
}

type SettlementWithdrawal struct {
	WithdrawID      string `json:"withdrawId"`
	Owner           string `json:"owner"`
	Denom           string `json:"denom"`
	Amount          string `json:"amount"`
	Destination     string `json:"destination"`
	DestinationHash string `json:"destinationHash"`
	Nullifier       string `json:"nullifier"`
}

type SettlementUpdate struct {
	BatchID      string                 `json:"batchId"`
	OldStateRoot string                 `json:"oldStateRoot"`
	NewStateRoot string                 `json:"newStateRoot"`
	Deposits     []SettlementDeposit    `json:"deposits"`
	Withdrawals  []SettlementWithdrawal `json:"withdrawals"`
}

type BatchCommitments struct {
	DepositsRoot        string `json:"depositsRoot"`
	WithdrawalsRoot     string `json:"withdrawalsRoot"`
	NullifiersRoot      string `json:"nullifiersRoot"`
	WithdrawOutputsRoot string `json:"withdrawOutputsRoot"`
}

type WitnessAccount struct {
	Owner      string `json:"owner"`
	UserSecret string `json:"userSecret"`
	Nonce      string `json:"nonce"`
	OldBalance string `json:"oldBalance"`
	NewBalance string `json:"newBalance"`
}

type Witness struct {
	Accounts  []WitnessAccount `json:"accounts"`
	StatePath []string         `json:"statePath,omitempty"`
}

type ProveRequest struct {
	SettlementUpdate SettlementUpdate `json:"settlementUpdate"`
	BatchCommitments BatchCommitments `json:"batchCommitments"`
	Witness          Witness          `json:"witness"`

	// Trade is the ZK-T10 extension (APPEND-only, omitempty): when present, /prove
	// routes to the unified trade circuit (ZK-T09) and returns an 8-public-input
	// proofBundle. Core deposit/withdraw batches leave it nil and use the existing
	// path unchanged, so D's settle_loop HTTP shape is preserved.
	Trade *TradeProveRequest `json:"trade,omitempty"`
}

// TradeProveRequest carries the canonical trade batch (orders + fills + the
// derived witness the circuit needs) for the ZK-T10 /prove trade path. It mirrors
// the fields of the unified trade circuit's canonical batch.
type TradeProveRequest struct {
	Orders []TradeOrder `json:"orders"`
	Fills  []TradeFill  `json:"fills"`

	BidPrice   string `json:"bidPrice"`
	AskPrice   string `json:"askPrice"`
	FillPrice  string `json:"fillPrice"`
	MakerIsBid bool   `json:"makerIsBid"`

	Conservation TradeConservation `json:"conservation"`
	Cells        []TradeCell       `json:"cells"`

	DepositsRoot        string `json:"depositsRoot"`
	WithdrawalsRoot     string `json:"withdrawalsRoot"`
	NullifiersRoot      string `json:"nullifiersRoot"`
	WithdrawOutputsRoot string `json:"withdrawOutputsRoot"`
}

type TradeOrder struct {
	OrderHash string `json:"orderHash"`
	Owner     string `json:"owner"`
	Side      string `json:"side"`
	Price     string `json:"price"`
	Qty       string `json:"qty"`
	Remaining string `json:"remaining"`
	Filled    bool   `json:"filled"`
	Sequence  uint64 `json:"sequence"`
}

type TradeFill struct {
	TradeID        string `json:"tradeId"`
	Market         string `json:"market"`
	MakerOrderHash string `json:"makerOrderHash"`
	TakerOrderHash string `json:"takerOrderHash"`
	Price          string `json:"price"`
	Qty            string `json:"qty"`
	MakerFee       string `json:"makerFee"`
	TakerFee       string `json:"takerFee"`
	Buyer          string `json:"buyer"`
	Seller         string `json:"seller"`
}

type TradeConservation struct {
	Price                    string `json:"price"`
	Qty                      string `json:"qty"`
	MakerFee                 string `json:"makerFee"`
	TakerFee                 string `json:"takerFee"`
	BuyerIsMaker             bool   `json:"buyerIsMaker"`
	BuyerReservedQuoteBefore string `json:"buyerReservedQuoteBefore"`
	SellerReservedBaseBefore string `json:"sellerReservedBaseBefore"`
}

type TradeCell struct {
	Owner      string `json:"owner"`
	Denom      string `json:"denom"`
	OldBalance string `json:"oldBalance"`
	DeltaIn    string `json:"deltaIn"`
	DeltaOut   string `json:"deltaOut"`
}

type ProofBundle struct {
	Proof             string   `json:"proof"`
	PublicInputs      []string `json:"publicInputs"`
	VerificationKeyID string   `json:"verificationKeyId"`
}

type ProveResponse struct {
	ProofBundle ProofBundle `json:"proofBundle"`
}

type VerifyRequest struct {
	SettlementUpdate SettlementUpdate `json:"settlementUpdate"`
	BatchCommitments BatchCommitments `json:"batchCommitments"`
	ProofBundle      ProofBundle      `json:"proofBundle"`
}

type VerifyResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// VerifierArtifact is the portable verifier-side artifact exported by gazk.
//
// It lets downstream P1/on-chain integration map a proofBundle.verificationKeyId
// to the verifying key bytes and public input contract expected by that proof.
type VerifierArtifact struct {
	VerificationKeyID string   `json:"verificationKeyId"`
	HashMode          string   `json:"hashMode"`
	Curve             string   `json:"curve"`
	Backend           string   `json:"backend"`
	PublicInputCount  int      `json:"publicInputCount"`
	PublicInputNames  []string `json:"publicInputNames"`
	VerifyingKey      string   `json:"verifyingKey"`
}

// TradeVerifyRequest is the trade-verifier request envelope (ZK-T02). It mirrors
// VerifyRequest but carries the caller-reconstructed 8 trade public inputs
// explicitly, because SettlementUpdate does not carry trades yet.
type TradeVerifyRequest struct {
	SettlementUpdate SettlementUpdate `json:"settlementUpdate"`
	ProofBundle      ProofBundle      `json:"proofBundle"`
	PublicInputs     []string         `json:"publicInputs"`
}

// TradeVerifierArtifact is the portable verifier-side contract for the trade
// circuit. In ZK-T02 it advertises the published vkId + the locked 8
// public-input layout; Stub=true and VerifyingKey empty until ZK-T09 mints the
// real key.
type TradeVerifierArtifact struct {
	VerificationKeyID string   `json:"verificationKeyId"`
	Curve             string   `json:"curve"`
	Backend           string   `json:"backend"`
	PublicInputCount  int      `json:"publicInputCount"`
	PublicInputNames  []string `json:"publicInputNames"`
	VerifyingKey      string   `json:"verifyingKey,omitempty"`
	Stub              bool     `json:"stub"`
}
