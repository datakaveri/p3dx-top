package services

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWKS is the JSON Web Key Set returned by Keycloak.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is a single JSON Web Key (RSA).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// FetchKeycloakJWKS fetches the JWKS from KEYCLOAK_JWKS_URL and returns RSA public keys.
// Keys are indexed by kid; if kid is empty, the first key is used.
func FetchKeycloakJWKS() (map[string]*rsa.PublicKey, error) {
	jwksURL := os.Getenv("KEYCLOAK_JWKS_URL")
	if jwksURL == "" {
		return nil, fmt.Errorf("KEYCLOAK_JWKS_URL not set")
	}
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS returned status %d", resp.StatusCode)
	}
	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" || jwk.N == "" || jwk.E == "" {
			continue
		}
		pub, err := jwkToRSAPublicKey(jwk)
		if err != nil {
			continue
		}
		kid := jwk.Kid
		if kid == "" {
			kid = "default"
		}
		keys[kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no RSA keys in JWKS")
	}
	return keys, nil
}

func jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e == 0 {
		e = 65537
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// ValidateAccessToken verifies a Keycloak JWT (e.g. access_token or id_token)
// using the realm JWKS from KEYCLOAK_JWKS_URL.
func ValidateAccessToken(tokenStr string) (*jwt.Token, error) {
	if tokenStr == "" {
		return nil, fmt.Errorf("empty token")
	}

	keysByKID, err := FetchKeycloakJWKS()
	if err != nil {
		return nil, err
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	return parser.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			// Some setups omit kid; try "default" if present.
			if pub, ok := keysByKID["default"]; ok {
				return pub, nil
			}
			return nil, fmt.Errorf("token header missing kid")
		}
		pub, ok := keysByKID[kid]
		if !ok {
			return nil, fmt.Errorf("kid %q not found in Keycloak JWKS", kid)
		}
		return pub, nil
	})
}

// RSAPublicKeyFromToken extracts an RSA public key that is bound to the token (DPoP/MTLS-style),
// typically carried in the standard `cnf.jwk` claim.
//
// Expected claim shape:
// {
//   "cnf": {
//     "jwk": { "kty":"RSA", "n":"...", "e":"..." }
//   }
// }
func RSAPublicKeyFromToken(t *jwt.Token) (*rsa.PublicKey, error) {
	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected token claims type")
	}

	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("token missing cnf claim")
	}
	jwkRaw, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("token cnf claim missing jwk")
	}

	kty, _ := jwkRaw["kty"].(string)
	n, _ := jwkRaw["n"].(string)
	e, _ := jwkRaw["e"].(string)
	if kty != "RSA" || n == "" || e == "" {
		return nil, fmt.Errorf("token cnf.jwk is not a valid RSA key")
	}

	return jwkToRSAPublicKey(JWK{Kty: kty, N: n, E: e})
}

// --- TEE attestation JWT verification and access token release ---

// TEE_ATTESTATION_JWKS_URL (env) is used to verify attestation JWTs signed by the TEE/attestation service.

// VerifyAttestationToken verifies a JWT that carries a TEE attestation report.
// The JWT must be signed with RS256 and verifiable using keys from TEE_ATTESTATION_JWKS_URL.
// Returns the parsed token on success.
func VerifyAttestationToken(tokenStr string) (*jwt.Token, error) {
	if tokenStr == "" {
		return nil, fmt.Errorf("empty attestation token")
	}
	jwksURL := os.Getenv("TEE_ATTESTATION_JWKS_URL")
	if jwksURL == "" {
		return nil, fmt.Errorf("TEE_ATTESTATION_JWKS_URL not set")
	}
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetch attestation JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attestation JWKS returned status %d", resp.StatusCode)
	}
	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode attestation JWKS: %w", err)
	}
	keysByKID := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" || jwk.N == "" || jwk.E == "" {
			continue
		}
		pub, err := jwkToRSAPublicKey(jwk)
		if err != nil {
			continue
		}
		kid := jwk.Kid
		if kid == "" {
			kid = "default"
		}
		keysByKID[kid] = pub
	}
	if len(keysByKID) == 0 {
		return nil, fmt.Errorf("no RSA keys in attestation JWKS")
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	return parser.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			if pub, ok := keysByKID["default"]; ok {
				return pub, nil
			}
			return nil, fmt.Errorf("attestation token header missing kid")
		}
		pub, ok := keysByKID[kid]
		if !ok {
			return nil, fmt.Errorf("kid %q not found in attestation JWKS", kid)
		}
		return pub, nil
	})
}

// IssueAccessToken creates a short-lived access token (JWT) signed by the orchestrator,
// for use after successful TEE attestation. Signing key is read from ORCH_PRIVATE_KEY.
func IssueAccessToken(subject string, extraClaims map[string]any) (string, error) {
	keyPath := os.Getenv("ORCH_PRIVATE_KEY")
	if keyPath == "" {
		return "", fmt.Errorf("ORCH_PRIVATE_KEY not set")
	}
	priv, err := LoadPrivateKey(keyPath)
	if err != nil {
		return "", fmt.Errorf("load orchestrator key: %w", err)
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": subject,
		"iat": float64(now.Unix()),
		"exp": float64(now.Add(1 * time.Hour).Unix()),
		"iss": "top-orchestrator",
	}
	for k, v := range extraClaims {
		claims[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(priv)
}
