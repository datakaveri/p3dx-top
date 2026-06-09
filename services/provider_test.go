package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestProviderApprovalSuccess(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}

		var req providerApprovalRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Contract["id"] != "contract1" {
			t.Errorf("contract id = %v, want contract1", req.Contract["id"])
		}
		if req.Claims["sub"] != "user1" {
			t.Errorf("claim sub = %v, want user1", req.Claims["sub"])
		}

		json.NewEncoder(w).Encode(providerApprovalResponse{
			Approved: true,
			Reason:   "approved",
		})
	}))
	defer server.Close()

	t.Setenv("DATA_PROVIDER_APPROVAL_URL", server.URL)

	approved, reason, err := RequestProviderApproval(
		map[string]interface{}{"id": "contract1"},
		map[string]interface{}{"sub": "user1"},
	)
	if err != nil {
		t.Fatalf("RequestProviderApproval() error = %v", err)
	}
	if !approved {
		t.Fatal("RequestProviderApproval() approved = false, want true")
	}
	if reason != "approved" {
		t.Errorf("reason = %q, want approved", reason)
	}
	if !called {
		t.Fatal("provider server was not called")
	}
}

func TestRequestProviderApprovalRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(providerApprovalResponse{
			Approved: false,
			Reason:   "provider rejected contract",
		})
	}))
	defer server.Close()

	t.Setenv("DATA_PROVIDER_APPROVAL_URL", server.URL)

	approved, reason, err := RequestProviderApproval(
		map[string]interface{}{"id": "contract1"},
		map[string]interface{}{"sub": "user1"},
	)
	if err != nil {
		t.Fatalf("RequestProviderApproval() error = %v", err)
	}
	if approved {
		t.Fatal("RequestProviderApproval() approved = true, want false")
	}
	if reason != "provider rejected contract" {
		t.Errorf("reason = %q, want provider rejected contract", reason)
	}
}

func TestRequestProviderApprovalNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	t.Setenv("DATA_PROVIDER_APPROVAL_URL", server.URL)

	approved, reason, err := RequestProviderApproval(
		map[string]interface{}{"id": "contract1"},
		map[string]interface{}{"sub": "user1"},
	)
	if err == nil {
		t.Fatal("RequestProviderApproval() error = nil, want error")
	}
	if approved {
		t.Fatal("RequestProviderApproval() approved = true, want false")
	}
	if reason != "" {
		t.Errorf("reason = %q, want empty", reason)
	}
}

func TestRequestProviderApprovalInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{invalid json"))
	}))
	defer server.Close()

	t.Setenv("DATA_PROVIDER_APPROVAL_URL", server.URL)

	approved, reason, err := RequestProviderApproval(
		map[string]interface{}{"id": "contract1"},
		map[string]interface{}{"sub": "user1"},
	)
	if err == nil {
		t.Fatal("RequestProviderApproval() error = nil, want error")
	}
	if approved {
		t.Fatal("RequestProviderApproval() approved = true, want false")
	}
	if reason != "" {
		t.Errorf("reason = %q, want empty", reason)
	}
}

func TestRequestProviderApprovalMissingURL(t *testing.T) {
	t.Setenv("DATA_PROVIDER_APPROVAL_URL", "")

	approved, reason, err := RequestProviderApproval(
		map[string]interface{}{"id": "contract1"},
		map[string]interface{}{"sub": "user1"},
	)
	if err == nil {
		t.Fatal("RequestProviderApproval() error = nil, want error")
	}
	if approved {
		t.Fatal("RequestProviderApproval() approved = true, want false")
	}
	if reason != "" {
		t.Errorf("reason = %q, want empty", reason)
	}
}
