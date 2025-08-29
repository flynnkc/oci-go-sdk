package auth

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestTokenExchangeKeyProvider(t *testing.T) {
	// Create a new tokenExchangeKeyProvider instance
	kp, err := newTokenExchangeKeyProvider("https://example.com", "client-id", "client-secret", common.Region("us-ashburn-1"), func(args ...interface{}) (string, error) {
		// implement your token exchange logic here
		return "jwt-token", nil
	})

	if err != nil {
		t.Errorf("newTokenExchangeKeyProvider returned error: %v", err)
	}

	// Test the PrivateRSAKey method
	privateKey, err := kp.PrivateRSAKey()
	if err != nil {
		t.Errorf("PrivateRSAKey returned error: %v", err)
	}

	if privateKey == nil {
		t.Errorf("PrivateRSAKey returned nil private key")
	}

	// Test the KeyID method
	keyID, err := kp.KeyID()
	if err != nil {
		t.Errorf("KeyID returned error: %v", err)
	}

	if keyID == "" {
		t.Errorf("KeyID returned empty key ID")
	}
}
