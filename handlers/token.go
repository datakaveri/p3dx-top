package handlers

import (
	"encoding/json"
	"net/http"
	"top/services"

	"github.com/golang-jwt/jwt/v5"
)

// TokenRequest is the body for the attestation-based token endpoint.
type TokenRequest struct {
	AttestationToken string `json:"attestation_token"`
}

// TokenResponse is returned on successful attestation verification.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// HandleToken receives a JWT that carries a TEE attestation report, verifies it,
// and on success releases a short-lived access token.
func HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.AttestationToken == "" {
		http.Error(w, "attestation_token is required", http.StatusBadRequest)
		return
	}

	// Verify the TEE attestation JWT (signature and claims)
	parsed, err := services.VerifyAttestationToken(req.AttestationToken)
	if err != nil || !parsed.Valid {
		http.Error(w, "Invalid or expired attestation token", http.StatusUnauthorized)
		return
	}

	// Optional: assert attestation-specific claims (e.g. x-ms-attestation-type, measurements)
	subject := "tee-attested"
	if claims, ok := parsed.Claims.(jwt.MapClaims); ok {
		if sub, _ := claims["sub"].(string); sub != "" {
			subject = sub
		}
	}

	// Release access token on successful verification
	accessToken, err := services.IssueAccessToken(subject, nil)
	if err != nil {
		http.Error(w, "Failed to issue access token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})
}
