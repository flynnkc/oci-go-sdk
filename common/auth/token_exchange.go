package auth

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/common"
)

const (
	tokenExchangeGrant          string = "grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
	tokenExchangeRequestedToken string = "requested_token_type=urn:oci:token-type:oci-upst"
)

type configurationProviderForTokenExchange struct {
	TokenExchangeKeyProvider
}

func NewConfigurationProviderForTokenExchange() common.ConfigurationProvider {
	return &configurationProviderForTokenExchange{
		TokenExchangeKeyProvider: TokenExchangeKeyProvider{},
	}
}

func (c *configurationProviderForTokenExchange) TenancyOCID() (string, error) {
	claim, ok := c.token.payload["tenant"].(string)
	if !ok {
		return "", ErrNoSuchClaim
	}

	return claim, nil
}

func (c *configurationProviderForTokenExchange) UserOCID() (string, error) {
	claim, ok := c.token.payload["sub"].(string)
	if !ok {
		return "", ErrNoSuchClaim
	}

	return claim, nil
}

func (c *configurationProviderForTokenExchange) KeyFingerprint() (string, error) {

	// Marshal the public key to DER format
	publicKeyDER, err := x509.MarshalPKIXPublicKey(c.privateKey.Public())
	if err != nil {
		return "", err
	}

	// Hash the public key using SHA256
	hash := sha256.Sum256(publicKeyDER)

	// Encode the hash as a hexadecimal string
	fingerprint := hex.EncodeToString(hash[:])

	// Format the fingerprint as a colon-separated hexadecimal string
	formattedFingerprint := ""
	for i, b := range hash {
		formattedFingerprint += fmt.Sprintf("%02x", b)
		if i < len(hash)-1 {
			formattedFingerprint += ":"
		}
	}

	return fingerprint, nil
}

func (c *configurationProviderForTokenExchange) Region() (string, error) {

	return c.region, nil
}

func (c *configurationProviderForTokenExchange) AuthType() (common.AuthConfig, error) {

	return common.AuthConfig{
		AuthType:         common.UnknownAuthenticationType,
		IsFromConfigFile: false,
	}, nil
}
