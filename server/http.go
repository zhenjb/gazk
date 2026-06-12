package server

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/zhenjb/gazk/contract"
	"github.com/zhenjb/gazk/prover"
)

type HTTPServer struct {
	prover *prover.Service
}

func NewHTTPServer(proverService *prover.Service) *HTTPServer {
	if proverService == nil {
		proverService = prover.NewService()
	}

	return &HTTPServer{
		prover: proverService,
	}
}

func (s *HTTPServer) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.Health)
	mux.HandleFunc("GET /verifier-artifact", s.VerifierArtifact)
	mux.HandleFunc("POST /prove", s.Prove)
	mux.HandleFunc("POST /verify", s.Verify)

	return mux
}

func (s *HTTPServer) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":            "ok",
		"service":           "gazk",
		"verificationKeyId": s.prover.VerificationKeyID(),
		"hashMode":          s.prover.HashMode().String(),
		"hashV1Id":          prover.HashV1ID,
	})
}

func (s *HTTPServer) Prove(w http.ResponseWriter, r *http.Request) {
	var req contract.ProveRequest
	if !readJSON(w, r, &req) {
		return
	}

	proofBundle, err := s.prover.Prove(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, contract.ProveResponse{
		ProofBundle: proofBundle,
	})
}

func (s *HTTPServer) Verify(w http.ResponseWriter, r *http.Request) {
	var req contract.VerifyRequest
	if !readJSON(w, r, &req) {
		return
	}

	err := s.prover.Verify(req)
	if err != nil {
		writeJSON(w, http.StatusOK, contract.VerifyResponse{
			Valid: false,
			Error: err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, contract.VerifyResponse{
		Valid: true,
	})
}

func readJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(out); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}

	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, contract.ErrorResponse{
		Error: message,
	})
}

func (s *HTTPServer) VerifierArtifact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	artifact, err := s.prover.VerifierArtifact()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, artifact)
}
