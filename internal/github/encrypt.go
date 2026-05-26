package github

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// EncryptSecret encrypts a plaintext secret value using the recipient's public key (base64 encoded).
// This generates a Libsodium-compatible sealed box payload required by the GitHub Actions Secrets API.
func EncryptSecret(recipientPubKeyB64 string, secretText string) (string, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(recipientPubKeyB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode recipient public key: %w", err)
	}

	if len(pubKeyBytes) != 32 {
		return "", fmt.Errorf("invalid recipient public key length: expected 32 bytes, got %d", len(pubKeyBytes))
	}

	var recipientKey [32]byte
	copy(recipientKey[:], pubKeyBytes)

	// box.SealAnonymous seals a message using ephemeral keys (making it an anonymous sealed box)
	encrypted, err := box.SealAnonymous(nil, []byte(secretText), &recipientKey, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to seal secret anonymous box: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}
