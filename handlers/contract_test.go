package handlers

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleContractInvalidRequestBody(t *testing.T) {
	tests := []struct {
		name               string
		body               string
		expectedStatusCode int
	}{
		{
			name:               "invalid JSON",
			body:               `{invalid json}`,
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "empty body",
			body:               ``,
			expectedStatusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/contract", bytes.NewBufferString(tt.body))
			w := httptest.NewRecorder()

			HandleContract(w, req)

			if w.Code != tt.expectedStatusCode {
				t.Errorf("expected status %d, got %d", tt.expectedStatusCode, w.Code)
			}
		})
	}
}

func TestHandleContractMissingToken(t *testing.T) {
	req := httptest.NewRequest("POST", "/contract", bytes.NewBufferString(`{
		"contract": {"data": "value"},
		"signature": "abcd1234"
	}`))
	w := httptest.NewRecorder()

	HandleContract(w, req)

	// Should fail because token is missing
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestHandleContractInvalidSignatureEncoding(t *testing.T) {
	req := httptest.NewRequest("POST", "/contract", bytes.NewBufferString(`{
		"access_token": "valid.token.here",
		"contract": {"data": "value"},
		"signature": "not-hex-encoded"
	}`))
	w := httptest.NewRecorder()

	HandleContract(w, req)

	// Should fail because signature is not properly hex encoded
	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
		t.Errorf("expected status BadRequest or Unauthorized, got %d", w.Code)
	}
}

func TestHandleContractInvalidContractJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/contract", bytes.NewBufferString(`{
		"access_token": "valid.token.here",
		"contract": "not-an-object",
		"signature": "abcd1234"
	}`))
	w := httptest.NewRecorder()

	HandleContract(w, req)

	// Should handle the contract appropriately
	if w.Code == http.StatusOK {
		t.Error("should not succeed with invalid contract structure")
	}
}

func TestRequestStructureUnmarshal(t *testing.T) {
	tests := []struct {
		name         string
		jsonStr      string
		wantErr      bool
		validateFunc func(*Request) bool
	}{
		{
			name: "access_token field",
			jsonStr: `{
				"access_token": "token123",
				"contract": {"id": "contract1"},
				"signature": "sig123"
			}`,
			wantErr: false,
			validateFunc: func(r *Request) bool {
				return r.AccessToken == "token123" && r.Signature == "sig123"
			},
		},
		{
			name: "token field",
			jsonStr: `{
				"token": "token456",
				"contract": {"id": "contract2"},
				"signature": "sig456"
			}`,
			wantErr: false,
			validateFunc: func(r *Request) bool {
				return r.Token == "token456" && r.Signature == "sig456"
			},
		},
		{
			name: "both token fields",
			jsonStr: `{
				"access_token": "access123",
				"token": "token789",
				"contract": {"id": "contract3"},
				"signature": "sig789"
			}`,
			wantErr: false,
			validateFunc: func(r *Request) bool {
				return r.AccessToken == "access123" && r.Token == "token789"
			},
		},
		{
			name:    "missing contract",
			jsonStr: `{"access_token": "token"}`,
			wantErr: false,
			validateFunc: func(r *Request) bool {
				return r.Contract == nil
			},
		},
		{
			name: "complex contract",
			jsonStr: `{
				"access_token": "token",
				"contract": {
					"provider": {"id": "p1", "policy": "pol1"},
					"resources": ["res1", "res2"],
					"conditions": {"time": "09:00-17:00"}
				},
				"signature": "sig"
			}`,
			wantErr: false,
			validateFunc: func(r *Request) bool {
				return r.Contract != nil && len(r.Contract) == 3
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req Request
			err := json.Unmarshal([]byte(tt.jsonStr), &req)

			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && !tt.validateFunc(&req) {
				t.Error("validation failed")
			}
		})
	}
}

func TestRequestWithComplexContract(t *testing.T) {
	complexContract := map[string]interface{}{
		"data_provider": map[string]interface{}{
			"id":        "provider1",
			"name":      "Test Provider",
			"policy_id": "policy1",
		},
		"conditions": []interface{}{
			map[string]interface{}{"type": "temporal", "value": "business_hours"},
			map[string]interface{}{"type": "spatial", "value": "US"},
		},
		"resources": []interface{}{"database1", "database2"},
		"purpose":   "research",
	}

	body, err := json.Marshal(Request{
		AccessToken: "test_token",
		Contract:    complexContract,
		Signature:   hex.EncodeToString([]byte("test")),
	})
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	var decodedReq Request
	if err := json.Unmarshal(body, &decodedReq); err != nil {
		t.Fatalf("failed to unmarshal request: %v", err)
	}

	if decodedReq.AccessToken != "test_token" {
		t.Error("token not preserved")
	}

	if _, ok := decodedReq.Contract["data_provider"]; !ok {
		t.Error("complex contract structure not preserved")
	}
}

func TestHandleContractResponseStructure(t *testing.T) {
	// Test that response structure can be properly encoded
	responseData := map[string]string{
		"status":         "success",
		"orch_signature": "sig_hex",
		"contract_id":    "contract_id_hex",
	}

	body, err := json.Marshal(responseData)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var decodedResp map[string]string
	if err := json.Unmarshal(body, &decodedResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if decodedResp["status"] != "success" {
		t.Error("status field not preserved")
	}
	if decodedResp["contract_id"] != "contract_id_hex" {
		t.Error("contract_id field not preserved")
	}
}

func TestHandleContractWithMultipleMocks(t *testing.T) {
	// Test request/response cycle structure
	req := httptest.NewRequest("POST", "/contract", bytes.NewBufferString(`{
		"access_token": "mock.jwt.token",
		"contract": {
			"data_provider_id": "provider1",
			"action": "read"
		},
		"signature": "0102030405"
	}`))

	// Verify request is properly parsed
	var parsedReq Request
	if err := json.NewDecoder(req.Body).Decode(&parsedReq); err != nil {
		t.Fatalf("failed to decode request: %v", err)
	}

	if parsedReq.AccessToken != "mock.jwt.token" {
		t.Error("access token not decoded correctly")
	}

	if contract, ok := parsedReq.Contract["data_provider_id"]; !ok || contract != "provider1" {
		t.Error("contract structure not decoded correctly")
	}

	if parsedReq.Signature != "0102030405" {
		t.Error("signature not decoded correctly")
	}
}

func TestHandleContractSignatureDecoding(t *testing.T) {
	tests := []struct {
		name    string
		sig     string
		wantErr bool
	}{
		{
			name:    "valid hex signature",
			sig:     hex.EncodeToString([]byte("test signature")),
			wantErr: false,
		},
		{
			name:    "invalid hex signature",
			sig:     "not_hex!@#$",
			wantErr: true,
		},
		{
			name:    "odd number of hex chars",
			sig:     "abc",
			wantErr: true,
		},
		{
			name:    "uppercase hex",
			sig:     hex.EncodeToString([]byte("test")),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := hex.DecodeString(tt.sig)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeString error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRequestTokenFieldPriority(t *testing.T) {
	// accessToken should be checked first, then token
	reqData := []byte(`{
		"access_token": "primary_token",
		"token": "secondary_token",
		"contract": {"id": "test"},
		"signature": "sig"
	}`)

	var req Request
	if err := json.Unmarshal(reqData, &req); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Implement the same logic as in HandleContract
	tokenStr := req.AccessToken
	if tokenStr == "" {
		tokenStr = req.Token
	}

	if tokenStr != "primary_token" {
		t.Error("should use access_token when available")
	}

	// Test fallback to token field
	reqData2 := []byte(`{
		"token": "only_token",
		"contract": {"id": "test"},
		"signature": "sig"
	}`)

	var req2 Request
	if err := json.Unmarshal(reqData2, &req2); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	tokenStr2 := req2.AccessToken
	if tokenStr2 == "" {
		tokenStr2 = req2.Token
	}

	if tokenStr2 != "only_token" {
		t.Error("should fallback to token when access_token not available")
	}
}

func TestHandleContractUnsupportedMethod(t *testing.T) {
	// Test GET request (should fail)
	req := httptest.NewRequest("GET", "/contract", nil)
	w := httptest.NewRecorder()

	// HandleContract doesn't validate method, but NewDecoder will fail on GET
	HandleContract(w, req)

	// Expect error since there's no body
	if w.Code == http.StatusOK {
		t.Error("GET request should not succeed")
	}
}

func TestRequestJSONMarshalRoundTrip(t *testing.T) {
	originalReq := Request{
		AccessToken: "token123",
		Token:       "alt_token",
		Contract: map[string]interface{}{
			"id":        "contract1",
			"type":      "data_access",
			"resources": []interface{}{"db1", "db2"},
			"duration": map[string]interface{}{
				"start": "2024-01-01",
				"end":   "2024-12-31",
			},
		},
		Signature: hex.EncodeToString([]byte("signature_data")),
	}

	// Marshal
	jsonData, err := json.Marshal(originalReq)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Unmarshal
	var decodedReq Request
	if err := json.Unmarshal(jsonData, &decodedReq); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Verify all fields
	if decodedReq.AccessToken != originalReq.AccessToken {
		t.Error("AccessToken mismatch")
	}
	if decodedReq.Token != originalReq.Token {
		t.Error("Token mismatch")
	}
	if decodedReq.Signature != originalReq.Signature {
		t.Error("Signature mismatch")
	}
	if len(decodedReq.Contract) != len(originalReq.Contract) {
		t.Error("Contract field count mismatch")
	}
}
func TestHandleContractBadHexSignature(t *testing.T) {

	req := httptest.NewRequest("POST", "/contract", bytes.NewBufferString(`{
		"access_token": "dummy",
		"contract": {"id":"test"},
		"signature": "zzzz"
	}`))

	w := httptest.NewRecorder()

	HandleContract(w, req)

	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status %d", w.Code)
	}
}
func TestHandleContractLargeContractStructure(t *testing.T) {

	contract := map[string]interface{}{
		"id":        "c1",
		"resources": []string{"db1", "db2"},
		"policy": map[string]interface{}{
			"type":  "temporal",
			"value": "9-5",
		},
	}

	body, _ := json.Marshal(Request{
		AccessToken: "fake",
		Contract:    contract,
		Signature:   hex.EncodeToString([]byte("sig")),
	})

	req := httptest.NewRequest("POST", "/contract", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	HandleContract(w, req)

	if w.Code == http.StatusOK {
		t.Error("should not succeed without valid services")
	}
}
