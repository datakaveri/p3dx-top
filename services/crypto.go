package services

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return priv, nil
}

// func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
// 	data, _ := os.ReadFile(path)
// 	block, _ := pem.Decode(data)
// 	return x509.ParsePKCS1PrivateKey(block.Bytes)
// }

func Sign(data []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
}

func Verify(data, sig []byte, pub *rsa.PublicKey) error {
	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig)
}
