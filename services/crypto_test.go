package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func generateKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	return priv, &priv.PublicKey
}

func writeKeyFile(t *testing.T, priv *rsa.PrivateKey) string {
	file, err := os.CreateTemp("", "key_*.pem")
	if err != nil {
		t.Fatalf("temp file creation failed: %v", err)
	}

	privBytes := x509.MarshalPKCS1PrivateKey(priv)

	err = pem.Encode(file, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	if err != nil {
		t.Fatalf("pem encode failed: %v", err)
	}

	file.Close()
	return file.Name()
}

func TestLoadPrivateKey(t *testing.T) {

	t.Run("valid key file", func(t *testing.T) {
		priv, _ := generateKeyPair(t)
		path := writeKeyFile(t, priv)
		defer os.Remove(path)

		key, err := LoadPrivateKey(path)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if key == nil {
			t.Fatal("expected key but got nil")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := LoadPrivateKey("does_not_exist.pem")

		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("invalid pem file", func(t *testing.T) {
		file, err := os.CreateTemp("", "bad_*.pem")
		if err != nil {
			t.Fatal(err)
		}

		file.WriteString("not a pem file")
		file.Close()

		defer os.Remove(file.Name())

		_, err = LoadPrivateKey(file.Name())

		if err == nil {
			t.Fatal("expected error for invalid pem")
		}
	})
}

func TestSignAndVerify(t *testing.T) {

	priv, pub := generateKeyPair(t)

	tests := []struct {
		name string
		data []byte
	}{
		{"normal data", []byte("hello world")},
		{"empty data", []byte("")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xFF}},
		{"large data", make([]byte, 10000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			sig, err := Sign(tt.data, priv)
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}

			if len(sig) == 0 {
				t.Fatal("signature should not be empty")
			}

			err = Verify(tt.data, sig, pub)

			if err != nil {
				t.Fatalf("verification failed: %v", err)
			}
		})
	}
}

func TestVerifyFailures(t *testing.T) {

	priv, pub := generateKeyPair(t)
	data := []byte("test message")

	sig, err := Sign(data, priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	t.Run("tampered data", func(t *testing.T) {

		tampered := append(data, 0x01)

		if err := Verify(tampered, sig, pub); err == nil {
			t.Fatal("expected verification failure")
		}
	})

	t.Run("tampered signature", func(t *testing.T) {

		badSig := append(sig, 0x01)

		if err := Verify(data, badSig, pub); err == nil {
			t.Fatal("expected verification failure")
		}
	})

	t.Run("empty signature", func(t *testing.T) {

		if err := Verify(data, []byte{}, pub); err == nil {
			t.Fatal("expected failure for empty signature")
		}
	})

	t.Run("wrong public key", func(t *testing.T) {

		_, wrongPub := generateKeyPair(t)

		if err := Verify(data, sig, wrongPub); err == nil {
			t.Fatal("verification should fail with wrong key")
		}
	})
}

func TestLoadKeyAndUseForSigning(t *testing.T) {

	priv, pub := generateKeyPair(t)

	path := writeKeyFile(t, priv)
	defer os.Remove(path)

	loaded, err := LoadPrivateKey(path)

	if err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}

	data := []byte("integration test")

	sig, err := Sign(data, loaded)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	if err := Verify(data, sig, pub); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}
