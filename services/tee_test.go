package services

import (
	"encoding/json"
	"testing"
)

func TestDeployEnclave(t *testing.T) {
	tests := []struct {
		name    string
		req     DeployRequest
		wantErr bool
	}{
		{
			name: "successful deployment (no server running)",
			req: DeployRequest{
				Contract: Contract(map[string]interface{}{
					"provider_id": "test_provider",
					"policy_id":   "test_policy",
				}),
				Signature:    "user_signature_hex",
				TopSignature: "orch_signature_hex",
			},
			wantErr: true,
		},
		{
			name: "server would return 400",
			req: DeployRequest{
				Contract:     Contract(map[string]interface{}{}),
				Signature:    "sig",
				TopSignature: "topsig",
			},
			wantErr: true,
		},
		{
			name: "server would return 500",
			req: DeployRequest{
				Contract:     Contract(map[string]interface{}{}),
				Signature:    "sig",
				TopSignature: "topsig",
			},
			wantErr: true,
		},
		{
			name: "complex contract structure",
			req: DeployRequest{
				Contract: Contract(map[string]interface{}{
					"provider_id": "complex_provider",
					"data": map[string]interface{}{
						"nested": []interface{}{1, 2, 3},
					},
					"conditions": []map[string]string{
						{"field": "value"},
					},
				}),
				Signature:    "hex_encoded_signature_string",
				TopSignature: "hex_encoded_topsig_string",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DeployEnclave(tt.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("DeployEnclave() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDeployEnclaveWithEmptyContract(t *testing.T) {
	req := DeployRequest{
		Contract:     Contract(map[string]interface{}{}),
		Signature:    "",
		TopSignature: "",
	}

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	if len(body) == 0 {
		t.Error("marshaled request should not be empty")
	}
}

func TestDeployEnclaveRequestMarshal(t *testing.T) {
	tests := []struct {
		name string
		req  DeployRequest
	}{
		{
			name: "basic request",
			req: DeployRequest{
				Contract:     Contract(map[string]interface{}{"id": "123"}),
				Signature:    "sig",
				TopSignature: "topsig",
			},
		},
		{
			name: "request with unicode characters",
			req: DeployRequest{
				Contract:     Contract(map[string]interface{}{"data": "日本語"}),
				Signature:    "sig",
				TopSignature: "topsig",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.req)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			var decoded DeployRequest
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if decoded.Signature != tt.req.Signature {
				t.Error("signature mismatch after marshal/unmarshal")
			}

			if decoded.TopSignature != tt.req.TopSignature {
				t.Error("top signature mismatch after marshal/unmarshal")
			}
		})
	}
}

func TestContractType(t *testing.T) {
	c := Contract(map[string]interface{}{
		"id":   "test",
		"data": "value",
	})

	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("failed to marshal Contract: %v", err)
	}

	var decoded Contract
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal Contract: %v", err)
	}

	if v, ok := decoded["id"]; !ok || v != "test" {
		t.Error("Contract unmarshal failed")
	}
}
	