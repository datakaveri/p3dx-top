package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type providerApprovalRequest struct {
	Contract map[string]interface{} `json:"contract"`
	Claims   map[string]interface{} `json:"claims"`
}

type providerApprovalResponse struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason"`
}

func RequestProviderApproval(contract map[string]interface{}, claims map[string]interface{}) (approved bool, reason string, err error) {
	approvalURL := strings.TrimSpace(os.Getenv("DATA_PROVIDER_APPROVAL_URL"))
	if approvalURL == "" {
		return false, "", fmt.Errorf("DATA_PROVIDER_APPROVAL_URL not set")
	}

	body, err := json.Marshal(providerApprovalRequest{
		Contract: contract,
		Claims:   claims,
	})
	if err != nil {
		return false, "", fmt.Errorf("marshal provider approval request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, approvalURL, bytes.NewReader(body))
	if err != nil {
		return false, "", fmt.Errorf("create provider approval request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("request provider approval: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("provider approval endpoint returned status %d", resp.StatusCode)
	}

	var approval providerApprovalResponse
	if err := json.NewDecoder(resp.Body).Decode(&approval); err != nil {
		return false, "", fmt.Errorf("decode provider approval response: %w", err)
	}

	return approval.Approved, approval.Reason, nil
}
