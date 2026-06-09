package handlers

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"top/services"

	"github.com/golang-jwt/jwt/v5"
)

type Request struct {
	// Token can be sent either as `access_token` (matching Keycloak token response)
	AccessToken string                 `json:"access_token"`
	Token       string                 `json:"token"`
	Contract    map[string]interface{} `json:"contract"`
	Signature   string                 `json:"signature"` // hex-encoded user signature of the contract
}

var (
	validateAccessToken         = services.ValidateAccessToken
	rsaPublicKeyFromToken       = services.RSAPublicKeyFromToken
	verifySignature             = services.Verify
	authorizeContractAgainstAPD = services.AuthorizeContractAgainstAPD
	requestProviderApproval     = services.RequestProviderApproval
	loadPrivateKey              = services.LoadPrivateKey
	secureStore                 = services.SecureStore
	signContract                = services.Sign
	deployEnclave               = services.DeployEnclave
)

func HandleContract(w http.ResponseWriter, r *http.Request) {
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 1. Validate Keycloak token using Keycloak JWKS
	tokenStr := req.AccessToken
	if tokenStr == "" {
		tokenStr = req.Token
	}
	parsedToken, err := validateAccessToken(tokenStr)
	if err != nil || !parsedToken.Valid {
		http.Error(w, "Invalid Keycloak token", http.StatusUnauthorized)
		return
	}
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	// 2. Marshal contract (bytes that were signed)
	contractBytes, err := json.Marshal(req.Contract)
	if err != nil {
		http.Error(w, "Invalid contract", http.StatusBadRequest)
		return
	}

	// 3. Verify the user's signature on the contract using the public key bound to the token (cnf.jwk)
	userSig, err := hex.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "Invalid signature encoding", http.StatusBadRequest)
		return
	}
	userPub, err := rsaPublicKeyFromToken(parsedToken)
	if err != nil {
		http.Error(w, "Token missing bound public key", http.StatusUnauthorized)
		return
	}
	if err := verifySignature(contractBytes, userSig, userPub); err != nil {
		http.Error(w, "Contract signature verification failed", http.StatusUnauthorized)
		return
	}

	// 4. Authorize contract based on provider policy fetched from APD.
	allowed, err := authorizeContractAgainstAPD(req.Contract, claims)
	if err != nil {
		http.Error(w, "Policy authorization failed", http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, "User not authorized by provider policy", http.StatusForbidden)
		return
	}

	// 5. Request data-provider approval before storing, signing, or deploying the contract.
	approved, reason, err := requestProviderApproval(req.Contract, map[string]interface{}(claims))
	if err != nil {
		http.Error(w, "Data provider approval failed", http.StatusBadGateway)
		return
	}
	if !approved {
		message := "Data provider rejected contract"
		if reason != "" {
			message += ": " + reason
		}
		http.Error(w, message, http.StatusForbidden)
		return
	}

	// 6. Load orchestrator private key
	priv, _ := loadPrivateKey(os.Getenv("ORCH_PRIVATE_KEY"))

	// 7. Secure store
	storeKey := []byte(os.Getenv("STORE_KEY"))
	storePath := os.Getenv("STORE_PATH")

	contractID, err := secureStore(req.Contract, storeKey, storePath)
	if err != nil {
		http.Error(w, "Storage failed", 500)
		return
	}

	// 8. Sign contract with orchestrator key (over the same bytes)
	orchSig, _ := signContract(contractBytes, priv)

	// 9. Deploy to enclave (TEE)
	deployReq := services.DeployRequest{
		Contract:     services.Contract(req.Contract),
		Signature:    req.Signature,
		TopSignature: hex.EncodeToString(orchSig),
	}
	if err := deployEnclave(deployReq); err != nil {
		http.Error(w, "Enclave deployment failed", http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"status":         "success",
		"orch_signature": hex.EncodeToString(orchSig),
		"contract_id":    contractID,
	}

	json.NewEncoder(w).Encode(resp)
}
