package services

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSecureStore(t *testing.T) {
	tmpDir := t.TempDir()
	key := make([]byte, 32) // 256-bit key
	for i := range key {
		key[i] = byte(i)
	}

	tests := []struct {
		name     string
		contract interface{}
		key      []byte
		path     string
		wantErr  bool
	}{
		{
			name:     "store simple contract",
			contract: map[string]string{"data": "value"},
			key:      key,
			path:     tmpDir + string(filepath.Separator),
			wantErr:  false,
		},
		{
			name:     "store complex contract",
			contract: map[string]interface{}{"id": "123", "nested": map[string]string{"field": "value"}, "array": []int{1, 2, 3}},
			key:      key,
			path:     tmpDir + string(filepath.Separator),
			wantErr:  false,
		},
		{
			name:     "store contract with special characters",
			contract: map[string]string{"data": "special!@#$%^&*()"},
			key:      key,
			path:     tmpDir + string(filepath.Separator),
			wantErr:  false,
		},
		{
			name:     "store empty contract",
			contract: map[string]interface{}{},
			key:      key,
			path:     tmpDir + string(filepath.Separator),
			wantErr:  false,
		},
		{
			name:     "invalid key size",
			contract: map[string]string{"data": "value"},
			key:      []byte("short"),
			path:     tmpDir + string(filepath.Separator),
			wantErr:  true,
		},
		{
			name:     "invalid path",
			contract: map[string]string{"data": "value"},
			key:      key,
			path:     "/invalid/path/that/does/not/exist/",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contractID, err := SecureStore(tt.contract, tt.key, tt.path)

			if (err != nil) != tt.wantErr {
				t.Errorf("SecureStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify contract ID is in hex format and correct length
				if len(contractID) != 64 { // SHA256 hex is 64 chars
					t.Errorf("SecureStore() contractID length = %d, want 64", len(contractID))
				}

				// Verify file was created
				expectedFile := tt.path + contractID + ".bin"
				if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
					t.Errorf("SecureStore() expected file %s not created", expectedFile)
				}

				// Cleanup
				os.Remove(expectedFile)
			}
		})
	}
}

func TestSecureStoreDecryption(t *testing.T) {
	tmpDir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	originalContract := map[string]interface{}{
		"provider_id": "test_provider",
		"policy_id":   "test_policy",
		"action":      "read",
	}

	contractID, err := SecureStore(originalContract, key, tmpDir+string(filepath.Separator))
	if err != nil {
		t.Fatalf("SecureStore() error = %v", err)
	}

	// Read and decrypt the stored file
	filePath := tmpDir + string(filepath.Separator) + contractID + ".bin"
	ciphertext, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read stored file: %v", err)
	}

	// Decrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	nonce := ciphertext[:nonceSize]
	decrypted, err := gcm.Open(nil, nonce, ciphertext[nonceSize:], nil)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	// Unmarshal and verify
	var storedContract map[string]interface{}
	if err := json.Unmarshal(decrypted, &storedContract); err != nil {
		t.Fatalf("failed to unmarshal contract: %v", err)
	}

	if storedContract["provider_id"] != originalContract["provider_id"] {
		t.Errorf("stored contract differs from original")
	}
}

func TestSecureStoreWithInvalidContract(t *testing.T) {
	tmpDir := t.TempDir()
	key := make([]byte, 32)

	tests := []struct {
		name     string
		contract interface{}
		wantErr  bool
	}{
		{
			name:     "contract with channel (non-JSON serializable)",
			contract: make(chan int),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SecureStore(tt.contract, key, tmpDir+string(filepath.Separator))
			if (err != nil) != tt.wantErr {
				t.Errorf("SecureStore() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSecureStoreUniqueIds(t *testing.T) {
	tmpDir := t.TempDir()
	key := make([]byte, 32)

	contract1 := map[string]string{"data": "value1"}
	contract2 := map[string]string{"data": "value2"}

	id1, err := SecureStore(contract1, key, tmpDir+string(filepath.Separator))
	if err != nil {
		t.Fatalf("first SecureStore() error = %v", err)
	}

	id2, err := SecureStore(contract2, key, tmpDir+string(filepath.Separator))
	if err != nil {
		t.Fatalf("second SecureStore() error = %v", err)
	}

	if id1 == id2 {
		t.Error("SecureStore() should generate different IDs for different contracts")
	}

	// Cleanup
	os.Remove(tmpDir + string(filepath.Separator) + id1 + ".bin")
	os.Remove(tmpDir + string(filepath.Separator) + id2 + ".bin")
}
