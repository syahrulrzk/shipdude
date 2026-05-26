package github

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestEncryptSecret_Roundtrip(t *testing.T) {
	// 1. Generate recipient key pair (equivalent to GitHub repository key)
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate box key pair: %v", err)
	}

	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])
	secretText := "my-secret-ssh-key-data-12345"

	// 2. Encrypt using our helper
	encryptedB64, err := EncryptSecret(pubKeyB64, secretText)
	if err != nil {
		t.Fatalf("failed to encrypt secret: %v", err)
	}

	// 3. Decode encrypted payload
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		t.Fatalf("failed to decode encrypted base64: %v", err)
	}

	// 4. Open the anonymous sealed box
	decryptedBytes, ok := box.OpenAnonymous(nil, encryptedBytes, pubKey, privKey)
	if !ok {
		t.Fatalf("failed to open sealed box")
	}

	// 5. Assertions
	decryptedText := string(decryptedBytes)
	if decryptedText != secretText {
		t.Errorf("decrypted secret mismatch. Expected '%s', got '%s'", secretText, decryptedText)
	}
}
