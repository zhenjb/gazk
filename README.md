# gazk

A gnark-based zero-knowledge prover service for GANC settlement batches.

## Current status

`gazk` is currently a contract-compatible prover shell.

It is designed to become the P2 ZK prover service used by `ganc-sys`.

Current capabilities:

- HTTP prover service.
- `GET /health`.
- `POST /prove`.
- `POST /verify`.
- `POST /verify` verifies Groth16 proof bytes for the current balance smoke circuit.
- `POST /prove` returns a `ProofBundle` with exactly 6 public inputs.
- `POST /prove` validates nullifier binding against `userSecret` and `nonce`.
- `POST /prove` validates destinationHash binding against `destination`.
- The current proof is a deterministic smoke placeholder.
- Settlement-specific gnark constraints will be added incrementally.

Current non-goals:

- This is not a production settlement circuit yet.
- This is not a proof-of-stake service.
- The existing cubic circuit is only a smoke/demo circuit.

## Contract

`gazk` follows the current GANC proof contract.

### Prove input

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
        "destinationHash": "0xdestination",
        "nullifier": "0xnullifier"
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

### Prove output

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

### Public input order

The public input order is locked:

```txt
publicInputs[0] = oldStateRoot
publicInputs[1] = newStateRoot
publicInputs[2] = depositsRoot
publicInputs[3] = withdrawalsRoot
publicInputs[4] = nullifiersRoot
publicInputs[5] = withdrawOutputsRoot
```

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

### Health

```bash
curl -s http://localhost:8090/health | jq
```

Expected response:

```json
{
  "service": "gazk",
  "status": "ok",
  "verificationKeyId": "gazk-balance-smoke-v1"
}
```

### Generate proof

```bash
curl -s -X POST http://localhost:8090/prove \
  -H "Content-Type: application/json" \
  -d '{
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
          "destinationHash": "0xdestination",
          "nullifier": "0xnullifier"
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
  }' | jq
```

Expected response shape:

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

### Verify proof

Use the same `settlementUpdate` and `batchCommitments` plus the returned `proofBundle`. The proof must be produced by the currently running `gazk` process because smoke proving/verifying keys are generated at startup.

```bash
curl -s -X POST http://localhost:8090/verify \
  -H "Content-Type: application/json" \
  -d '{
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
          "destinationHash": "0xdestination",
          "nullifier": "0xnullifier"
        }
      ]
    },
    "batchCommitments": {
      "depositsRoot": "0xdepositsRoot",
      "withdrawalsRoot": "0xwithdrawalsRoot",
      "nullifiersRoot": "0xnullifiersRoot",
      "withdrawOutputsRoot": "0xwithdrawOutputsRoot"
    },
    "proofBundle": {
      "proof": "0xexample",
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
  }' | jq
```

Expected response shape:

```json
{
  "valid": true
}
```

## Legacy smoke command

The old cubic demo path is still available for smoke testing:

```bash
go run main.go generate 3 35
```

This command is legacy/demo-only and should not be used as the GANC settlement proof contract.

## Development

### Format

```bash
gofmt -w .
```

### Test

```bash
go test ./...
```

### Tidy modules

```bash
go mod tidy
```

## Roadmap

### GAZK-01: Contract-compatible prover shell

Status: in progress.

Tasks:

- Define GANC proof contract types.
- Add HTTP `/health`, `/prove`, and `/verify`.
- Return `ProofBundle` with exactly 6 public inputs.
- Keep smoke proof placeholder while integration wiring is built.

### GAZK-02: Balance transition smoke circuit

Implement a settlement-shaped circuit with the constraint:

```txt
oldBalance + depositAmount - withdrawAmount = newBalance
```

Canonical Alice vector:

```txt
0 + 100 - 40 = 60
```

### GAZK-03: Nullifier binding

Status: service-level validation done.

Current binding:

    nullifier = SHA256("zkdex/nullifier/v0|userSecret|nonce")

This matches the current GANC placeholder hash. Circuit-level nullifier binding will be added after the final circuit-friendly hash is selected.

### GAZK-04: Destination hash binding

Status: service-level validation done.

Current binding:

    destinationHash = SHA256("zkdex/withdrawAddr/v0|destination")

This matches the current GANC placeholder hash. Circuit-level destination hash binding will be added after the final circuit-friendly hash is selected.

### GAZK-05: State root constraint

Bind the old and new state roots to the proved transition.

### GAZK-06: Real proof serialization

Replace the smoke proof placeholder with real gnark proof serialization.

### GAZK-07: P1 verifier integration

Expose a verifier function or artifact format that P1 can use inside `MsgSubmitBatchProof`.

## Integration boundary with ganc-sys

`ganc-sys` should call `gazk` as the P2 prover service.

Expected P4 flow:

```txt
POST /api/batch/build
-> settlementUpdate + batchCommitments + witness

POST gazk /prove
-> proofBundle

POST /api/batch/submit
-> settlementUpdate + batchCommitments + proofBundle
```

The P4 adapter must preserve the public input order exactly.

## Notes

This repository is intentionally incremental.

The first goal is contract compatibility with the current P3/P4 pending settlement flow. The real settlement constraints will replace the smoke proof internals step by step without changing the HTTP contract.

### GAZK-07: Harden proof verification

Status: done for the current smoke circuit.

`POST /verify` now checks:

    publicInputs length = 6
    publicInputs match settlementUpdate + batchCommitments
    publicInputs are non-empty 0x-prefixed values
    verificationKeyId matches the current service
    proof is valid 0x hex
    proof deserializes as a Groth16 proof
    Groth16 verification passes against the current balance smoke verifying key

Current limitation:

    Smoke proving/verifying keys are generated in-process at startup.
    Proofs are not guaranteed to verify across service restarts until key artifacts are persisted.


## Hash mode

`gazk` now has an explicit hash mode contract.

Default:

    GAZK_HASH_MODE=v0-sha256

Supported modes:

    v0-sha256
    v1-mimc

Current behavior:

    v0-sha256 is the default and is compatible with current ganc-sys.
    v1-mimc is enabled behind GAZK_HASH_MODE=v1-mimc for service-level nullifier and destinationHash validation. It is not the default yet and is not circuit-level binding yet.

Health exposes the active hash mode:

    curl -s http://localhost:8090/health | jq

Expected fields:

    hashMode
    hashV1Id
