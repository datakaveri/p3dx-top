package services

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func generateTestJWK(t *testing.T) (JWK, *rsa.PrivateKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA key generation failed: %v", err)
	}

	n := base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})

	return JWK{
		Kty: "RSA",
		Kid: "test-key",
		N:   n,
		E:   e,
	}, priv
}

func TestFetchKeycloakJWKS(t *testing.T) {

	jwk, _ := generateTestJWK(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []JWK{jwk},
		})
	}))
	defer server.Close()

	t.Setenv("KEYCLOAK_JWKS_URL", server.URL)

	keys, err := FetchKeycloakJWKS()

	if err != nil {
		t.Fatalf("FetchKeycloakJWKS failed: %v", err)
	}

	if keys["test-key"] == nil {
		t.Fatal("expected RSA key not returned")
	}
}

func TestFetchKeycloakJWKSInvalidJSON(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "invalid json")
	}))
	defer server.Close()

	t.Setenv("KEYCLOAK_JWKS_URL", server.URL)

	_, err := FetchKeycloakJWKS()

	if err == nil {
		t.Fatal("expected JSON decode error")
	}
}

func TestFetchKeycloakJWKSHTTPError(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	t.Setenv("KEYCLOAK_JWKS_URL", server.URL)

	_, err := FetchKeycloakJWKS()

	if err == nil {
		t.Fatal("expected HTTP status error")
	}
}

func TestJWKToRSAPublicKey(t *testing.T) {

	jwk, _ := generateTestJWK(t)

	pub, err := jwkToRSAPublicKey(jwk)

	if err != nil {
		t.Fatalf("jwkToRSAPublicKey failed: %v", err)
	}

	if pub == nil {
		t.Fatal("expected RSA public key")
	}
}

func TestValidateAccessToken(t *testing.T) {

	jwk, priv := generateTestJWK(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []JWK{jwk},
		})
	}))
	defer server.Close()

	t.Setenv("KEYCLOAK_JWKS_URL", server.URL)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "user1",
	})

	token.Header["kid"] = "test-key"

	tokenStr, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("token signing failed: %v", err)
	}

	parsed, err := ValidateAccessToken(tokenStr)

	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	if !parsed.Valid {
		t.Fatal("token should be valid")
	}
}

func TestValidateAccessTokenEmpty(t *testing.T) {

	_, err := ValidateAccessToken("")

	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestRSAPublicKeyFromToken(t *testing.T) {

	jwk, _ := generateTestJWK(t)

	claims := jwt.MapClaims{
		"cnf": map[string]interface{}{
			"jwk": map[string]interface{}{
				"kty": jwk.Kty,
				"n":   jwk.N,
				"e":   jwk.E,
			},
		},
	}

	token := &jwt.Token{
		Claims: claims,
	}

	pub, err := RSAPublicKeyFromToken(token)

	if err != nil {
		t.Fatalf("RSAPublicKeyFromToken failed: %v", err)
	}

	if pub == nil {
		t.Fatal("expected RSA public key")
	}
}

func TestRSAPublicKeyFromTokenMissingCNF(t *testing.T) {

	token := &jwt.Token{
		Claims: jwt.MapClaims{
			"sub": "user",
		},
	}

	_, err := RSAPublicKeyFromToken(token)

	if err == nil {
		t.Fatal("expected error for missing cnf claim")
	}
}
