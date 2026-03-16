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
	AccessToken string                 `json:"access_token"`
	Token       string                 `json:"token"`
	Contract    map[string]interface{} `json:"contract"`
	Signature   string                 `json:"signature"`
}

func HandleContract(w http.ResponseWriter, r *http.Request) {

	var req Request

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 1 Validate Keycloak token
	tokenStr := req.AccessToken
	if tokenStr == "" {
		tokenStr = req.Token
	}

	parsedToken, err := services.ValidateAccessToken(tokenStr)
	if err != nil || !parsedToken.Valid {
		http.Error(w, "Invalid Keycloak token", http.StatusUnauthorized)
		return
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	// 2 Marshal contract
	contractBytes, err := json.Marshal(req.Contract)
	if err != nil {
		http.Error(w, "Invalid contract", http.StatusBadRequest)
		return
	}

	// 3 Verify user signature
	userSig, err := hex.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "Invalid signature encoding", http.StatusBadRequest)
		return
	}

	userPub, err := services.RSAPublicKeyFromToken(parsedToken)
	if err != nil {
		http.Error(w, "Token missing bound public key", http.StatusUnauthorized)
		return
	}

	if err := services.Verify(contractBytes, userSig, userPub); err != nil {
		http.Error(w, "Contract signature verification failed", http.StatusUnauthorized)
		return
	}

	// 4 Authorize contract against APD policy
	allowed, err := services.AuthorizeContractAgainstAPD(req.Contract, claims)
	if err != nil {
		http.Error(w, "Policy authorization failed", http.StatusInternalServerError)
		return
	}

	if !allowed {
		http.Error(w, "User not authorized by provider policy", http.StatusForbidden)
		return
	}

	// 5 Load orchestrator private key
	priv, err := services.LoadPrivateKey(os.Getenv("ORCH_PRIVATE_KEY"))
	if err != nil {
		http.Error(w, "Failed to load orchestrator key", http.StatusInternalServerError)
		return
	}

	// 6 Secure store contract
	storeKey := []byte(os.Getenv("STORE_KEY"))
	storePath := os.Getenv("STORE_PATH")

	contractID, err := services.SecureStore(req.Contract, storeKey, storePath)
	if err != nil {
		http.Error(w, "Storage failed", http.StatusInternalServerError)
		return
	}

	// 7 Sign contract with orchestrator key
	orchSig, err := services.Sign(contractBytes, priv)
	if err != nil {
		http.Error(w, "Signing failed", http.StatusInternalServerError)
		return
	}

	// ---------------------------
	// NEW STEP
	// ---------------------------

	appID, ok := req.Contract["application"].(string)
	if !ok || appID == "" {
		http.Error(w, "Contract missing application field", http.StatusBadRequest)
		return
	}

	appPayload, err := services.FetchApplicationFromConMan(appID)
	if err != nil {
		http.Error(w, "Failed to fetch application from ConMan", http.StatusInternalServerError)
		return
	}

	// ---------------------------
	// 8 Deploy enclave
	// ---------------------------

	deployReq := services.DeployRequest{
		Contract:        services.Contract(req.Contract),
		Signature:       req.Signature,
		TopSignature:    hex.EncodeToString(orchSig),
		ApplicationBlob: appPayload,
	}

	if err := services.DeployEnclave(deployReq); err != nil {
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
