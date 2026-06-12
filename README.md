# gazk

`gazk` is the P2 zero-knowledge prover service for the GANC / ZKDEX settlement flow.

It generates and verifies real Groth16 proofs with `gnark`, exposes proof services over HTTP, persists prover keys, and exports verifier artifacts for downstream P1/on-chain integration.

## Role in the system

`gazk` sits between the off-chain batch builder and the on-chain settlement module.

```txt
P3/P4 off-chain batch builder
  -> settlementUpdate + batchCommitments + witness
  -> gazk /prove
  -> proofBundle
  -> P4 relayer
  -> P1 x/zkdex MsgSubmitBatchProof
```

The main output of `gazk` is:

```json
{
  "proofBundle": {
    "proof": "0x...",
    "publicInputs": ["0x...", "0x...", "0x...", "0x...", "0x...", "0x..."],
    "verificationKeyId": "gazk-balance-smoke-v1"
  }
}
```

## Current status

Current MVP status:

- Real `gnark` + Groth16 proof generation.
- Real Groth16 proof verification.
- HTTP API:
  - `GET /health`
  - `POST /prove`
  - `POST /verify`
  - `GET /verifier-artifact`
- CLI verifier artifact export.
- Persisted proving/verifying keys via `GAZK_KEY_DIR`.
- Stable `ProofBundle` contract with exactly 6 public inputs.
- Default `v0-sha256` mode compatible with current `ganc-sys`.
- Opt-in `v1-mimc` mode with a stronger settlement circuit.

The ZK MVP is complete enough for integration with P1/P4.

## What is proven

### Default mode: `v0-sha256`

Default mode is designed for compatibility with the current `ganc-sys` remote prover flow.

```txt
GAZK_HASH_MODE=v0-sha256
```

The default circuit proves the balance transition:

```txt
oldBalance + depositAmount = newBalance + withdrawAmount
```

For the canonical Alice vector:

```txt
0 + 100 = 60 + 40
```

In this mode, `nullifier` and `destinationHash` are validated at service level using the current `ganc-sys` SHA-256-compatible encoding.

This mode is the default because the current backend integration depends on it.

### Opt-in mode: `v1-mimc`

```txt
GAZK_HASH_MODE=v1-mimc
```

`v1-mimc` uses a combined settlement circuit that proves:

```txt
1. oldBalance + depositAmount = newBalance + withdrawAmount
2. nullifier = MiMC(secretField, nonceField)
3. destinationHash = MiMC(destinationField)
4. oldStateRoot = MiMC(ownerField, oldBalance)
5. newStateRoot = MiMC(ownerField, newBalance)
```

The `oldStateRoot` / `newStateRoot` relation is currently a single-account state-root placeholder. It is circuit-level binding, but it is not a full Merkle multi-account state tree yet.

## Non-goals for the current MVP

The current implementation is not trying to solve these yet:

- Full Merkle tree state transition.
- Multi-account batch proof inside the circuit.
- Production-grade hash/preimage encoding.
- On-chain Cosmos verifier implementation.
- Proof aggregation.
- Performance optimization / benchmarking.

Those belong to the next stage after P1/P4 wiring.

## Contract

### Prove request

`POST /prove`

```json
{
  "settlementUpdate": {
    "batchId": "batch-1",
    "oldStateRoot": "0xrootA",
    "newStateRoot": "0xrootB",
    "deposits": [
      {
        "depositId": "dep-1",
        "owner": "cosmos1alice",
        "denom": "uusdc",
        "amount": "100"
      }
    ],
    "withdrawals": [
      {
        "withdrawId": "wd-1",
        "owner": "cosmos1alice",
        "denom": "uusdc",
        "amount": "40",
        "destination": "cosmos1alice",
        "destinationHash": "0x...",
        "nullifier": "0x..."
      }
    ]
  },
  "batchCommitments": {
    "depositsRoot": "0xdepositsRoot",
    "withdrawalsRoot": "0xwithdrawalsRoot",
    "nullifiersRoot": "0xnullifiersRoot",
    "withdrawOutputsRoot": "0xwithdrawOutputsRoot"
  },
  "witness": {
    "accounts": [
      {
        "owner": "cosmos1alice",
        "userSecret": "mock-user-secret",
        "nonce": "1",
        "oldBalance": "0",
        "newBalance": "60"
      }
    ]
  }
}
```

### Prove response

```json
{
  "proofBundle": {
    "proof": "0x...",
    "publicInputs": [
      "0xrootA",
      "0xrootB",
      "0xdepositsRoot",
      "0xwithdrawalsRoot",
      "0xnullifiersRoot",
      "0xwithdrawOutputsRoot"
    ],
    "verificationKeyId": "gazk-balance-smoke-v1"
  }
}
```

### Verify request

`POST /verify`

```json
{
  "settlementUpdate": {},
  "batchCommitments": {},
  "proofBundle": {
    "proof": "0x...",
    "publicInputs": [],
    "verificationKeyId": "..."
  }
}
```

### Verify response

```json
{
  "valid": true
}
```

If verification fails:

```json
{
  "valid": false,
  "error": "..."
}
```

## Public input order

The public input order is locked.

```txt
publicInputs[0] = settlementUpdate.oldStateRoot
publicInputs[1] = settlementUpdate.newStateRoot
publicInputs[2] = batchCommitments.depositsRoot
publicInputs[3] = batchCommitments.withdrawalsRoot
publicInputs[4] = batchCommitments.nullifiersRoot
publicInputs[5] = batchCommitments.withdrawOutputsRoot
```

Every consumer must preserve this order exactly:

- `gazk`
- `ganc-sys`
- P1 verifier
- P4 relayer
- test vectors

Changing this order breaks proof compatibility.

## HTTP API

### Start server

```bash
go run main.go server
```

Default address:

```txt
localhost:8090
```

Override address:

```bash
GAZK_ADDR=":8091" go run main.go server
```

Use persisted keys:

```bash
GAZK_KEY_DIR=.gazk/keys go run main.go server
```

Start in v1 mode:

```bash
GAZK_HASH_MODE=v1-mimc GAZK_KEY_DIR=.gazk/keys go run main.go server
```

### Health

```bash
curl -s http://localhost:8090/health | jq
```

Example response:

```json
{
  "hashMode": "v0-sha256",
  "hashV1Id": "bn254-mimc-v1",
  "service": "gazk",
  "status": "ok",
  "verificationKeyId": "gazk-balance-smoke-v1"
}
```

### Generate proof

Use `POST /prove` with the contract shown above.

```bash
curl -s -X POST http://localhost:8090/prove \
  -H "Content-Type: application/json" \
  -d @prove-request.json | jq
```

### Verify proof

Use the same `settlementUpdate`, same `batchCommitments`, and the returned `proofBundle`.

```bash
curl -s -X POST http://localhost:8090/verify \
  -H "Content-Type: application/json" \
  -d @verify-request.json | jq
```

### Export verifier artifact over HTTP

```bash
curl -s http://localhost:8090/verifier-artifact | jq
```

Example response shape:

```json
{
  "verificationKeyId": "gazk-balance-smoke-v1",
  "hashMode": "v0-sha256",
  "curve": "BN254",
  "backend": "groth16",
  "publicInputCount": 6,
  "publicInputNames": [
    "settlementUpdate.oldStateRoot",
    "settlementUpdate.newStateRoot",
    "batchCommitments.depositsRoot",
    "batchCommitments.withdrawalsRoot",
    "batchCommitments.nullifiersRoot",
    "batchCommitments.withdrawOutputsRoot"
  ],
  "verifyingKey": "0x..."
}
```

The `verificationKeyId` in this artifact must match `proofBundle.verificationKeyId`.

## CLI

### Export verifier artifact to file

Default v0 artifact:

```bash
GAZK_KEY_DIR=.gazk/keys \
go run main.go export-verifier-artifact artifacts/gazk-v0-verifier-artifact.json
```

v1 artifact:

```bash
GAZK_HASH_MODE=v1-mimc \
GAZK_KEY_DIR=.gazk/keys \
go run main.go export-verifier-artifact artifacts/gazk-v1-verifier-artifact.json
```

The generated `artifacts/` directory is local output and should not be committed unless the team intentionally decides to publish verifier artifacts.

### Legacy cubic demo

The legacy cubic demo command may still exist for old smoke testing:

```bash
go run main.go generate 3 35
```

Do not use this command for the GANC settlement proof path.

## Key persistence

By default, `gazk` sets up Groth16 proving/verifying keys in memory when an engine starts.

Set `GAZK_KEY_DIR` to persist keys:

```bash
GAZK_KEY_DIR=.gazk/keys go run main.go server
```

Behavior:

```txt
first start:
  compile circuit
  setup proving/verifying keys
  save keys under GAZK_KEY_DIR

later starts:
  compile circuit
  load proving/verifying keys from GAZK_KEY_DIR
```

Expected local key files:

```txt
.gazk/keys/gazk-balance-smoke-v1.proving.key
.gazk/keys/gazk-balance-smoke-v1.verifying.key
.gazk/keys/gazk-settlement-v1-mimc-nullifier-smoke-v1.proving.key
.gazk/keys/gazk-settlement-v1-mimc-nullifier-smoke-v1.verifying.key
```

`.gazk/` is ignored by git.

## Hash modes

Supported modes:

```txt
v0-sha256
v1-mimc
```

Default:

```txt
v0-sha256
```

Set mode:

```bash
GAZK_HASH_MODE=v1-mimc go run main.go server
```

### `v0-sha256`

Compatibility mode for current `ganc-sys`.

- Circuit: balance transition.
- Nullifier binding: service-level SHA-256 v0.
- Destination hash binding: service-level SHA-256 v0.
- Verification key ID: `gazk-balance-smoke-v1`.

### `v1-mimc`

Circuit-forward mode for P1/P2 integration.

- Circuit: balance + nullifier + destinationHash + state root placeholders.
- Hash: BN254 MiMC.
- Verification key ID: `gazk-settlement-v1-mimc-nullifier-smoke-v1`.

## Integration with ganc-sys

`ganc-sys` uses `gazk` as a remote prover.

Expected P4 flow:

```txt
POST /api/batch/build
  -> settlementUpdate + batchCommitments + witness

POST gazk /prove
  -> proofBundle

GET gazk /verifier-artifact
  -> verifier artifact metadata

POST /api/batch/submit
  -> settlementUpdate + batchCommitments + proofBundle
```

`ganc-sys` should validate:

```txt
proofBundle.publicInputs.length == 6
proofBundle.verificationKeyId is not empty
verifierArtifact.verificationKeyId == proofBundle.verificationKeyId
verifierArtifact.publicInputCount == len(proofBundle.publicInputs)
```

The current remote E2E uses the default `v0-sha256` mode.

## Integration with P1

P1 should treat `gazk` output as verifier input material.

P1 receives:

```txt
settlementUpdate
batchCommitments
proofBundle
verifier artifact / verifying key selected by verificationKeyId
```

P1 must derive or validate the same public input order:

```txt
oldStateRoot
newStateRoot
depositsRoot
withdrawalsRoot
nullifiersRoot
withdrawOutputsRoot
```

Then P1 verifies the Groth16 proof using the matching verifying key.

The verifier artifact can come from:

```txt
GET /verifier-artifact
```

or from a JSON file generated by:

```txt
go run main.go export-verifier-artifact <output.json>
```

## Development

Format:

```bash
gofmt -w .
```

Test:

```bash
go test ./...
```

Tidy modules:

```bash
go mod tidy
```

Run only prover tests:

```bash
go test ./prover -v
```

Run only server tests:

```bash
go test ./server -v
```

## Recommended local smoke flow

Terminal 1:

```bash
cd /workspaces/gazk
GAZK_KEY_DIR=.gazk/keys go run main.go server
```

Terminal 2:

```bash
curl -s http://localhost:8090/health | jq
curl -s http://localhost:8090/verifier-artifact | jq '{
  verificationKeyId,
  hashMode,
  curve,
  backend,
  publicInputCount,
  verifyingKeyPrefix: (.verifyingKey[0:20])
}'
```

With `ganc-sys` remote prover mode enabled, run the remote prover E2E from the backend repo:

```bash
cd /workspaces/ganc-sys
./scripts/e2e_pending_settlement_remote_prover_flow.sh
```

## Current implementation boundary

Done:

```txt
real proof generation
real off-chain verification
proof serialization
public input contract
key persistence
verifier artifact export
ganc-sys remote prover compatibility
```

Not done in this repository:

```txt
Cosmos SDK x/zkdex module
on-chain Groth16 verifier wiring
wallet signing
frontend
Merkle multi-account state tree
```

Those belong to P1/P4/P5 or the next ZK hardening stage.

