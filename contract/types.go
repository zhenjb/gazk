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
