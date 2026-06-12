package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zhenjb/gazk/contract"
	"github.com/zhenjb/gazk/prover"
)

func TestHTTPVerifierArtifact(t *testing.T) {
	handler := NewHTTPServer(prover.NewServiceWithHashMode(prover.HashModeV0SHA256.String())).Routes()

	req := httptest.NewRequest(http.MethodGet, "/verifier-artifact", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var artifact contract.VerifierArtifact
	if err := json.NewDecoder(rec.Body).Decode(&artifact); err != nil {
		t.Fatalf("decode verifier artifact: %v", err)
	}

	if artifact.VerificationKeyID != prover.VerificationKeyID {
		t.Fatalf("expected verificationKeyId=%q, got %q", prover.VerificationKeyID, artifact.VerificationKeyID)
	}

	if artifact.HashMode != prover.HashModeV0SHA256.String() {
		t.Fatalf("expected hashMode=%q, got %q", prover.HashModeV0SHA256.String(), artifact.HashMode)
	}

	if artifact.Curve != prover.VerifierArtifactCurve {
		t.Fatalf("expected curve=%q, got %q", prover.VerifierArtifactCurve, artifact.Curve)
	}

	if artifact.Backend != prover.VerifierArtifactBackend {
		t.Fatalf("expected backend=%q, got %q", prover.VerifierArtifactBackend, artifact.Backend)
	}

	if artifact.PublicInputCount != 6 {
		t.Fatalf("expected publicInputCount=6, got %d", artifact.PublicInputCount)
	}

	if len(artifact.PublicInputNames) != 6 {
		t.Fatalf("expected 6 publicInputNames, got %d", len(artifact.PublicInputNames))
	}

	if !strings.HasPrefix(artifact.VerifyingKey, "0x") {
		t.Fatalf("expected 0x-prefixed verifyingKey")
	}

	if len(artifact.VerifyingKey) <= 2 {
		t.Fatalf("expected non-empty verifyingKey")
	}
}
