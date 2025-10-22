package auth

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/common"
)

type TokenExchangeConfigurationProvider struct {
	keyProvider tokenExchangeKeyProvider
}

// TokenExchangeConfigurationProviderFromFunc creates a Configuration Provider from a
// function provided to retrieve a JWT an identity provider
func TokenExchangeConfigurationProviderFromFunc(domainEndpoint, clientId, clientSecret string,
	region common.Region,
	tokenFunc TokenExchangeFunc,
	args []interface{}) (common.ConfigurationProvider, error) {

	kp, err := newTokenExchangeKeyProvider(domainEndpoint, clientId, clientSecret,
		region, tokenFunc, args)
	if err != nil {
		common.Logf("unable to create configuration provider: %s", err)
		return TokenExchangeConfigurationProvider{}, err
	}

	// check for errors by trying to get token
	_, err = kp.KeyID()
	if err != nil {
		return TokenExchangeConfigurationProvider{}, err
	}

	return TokenExchangeConfigurationProvider{
		keyProvider: kp,
	}, nil
}

// TokenExchangeConfigurationProviderFromJWT returns a new configuration provider
// from a static User Principal Security Token (UPST)
func TokenExchangeConfigurationProviderFromJWT(jwt, domainEndpoint, clientId, clientSecret string,
	region common.Region) (common.ConfigurationProvider, error) {

	// Wrap the token in a func to give it the correct signature
	tokenFunc := func(args []interface{}) (string, error) {
		return jwt, nil
	}

	args := make([]interface{}, 0)

	return TokenExchangeConfigurationProviderFromFunc(domainEndpoint, clientId,
		clientSecret, region, tokenFunc, args)
}

func (c TokenExchangeConfigurationProvider) KeyID() (string, error) {
	return c.keyProvider.KeyID()
}

func (c TokenExchangeConfigurationProvider) PrivateRSAKey() (*rsa.PrivateKey, error) {
	return c.keyProvider.PrivateRSAKey()
}

// TenancyOCID provides the required receiver for the ConfigurationProvider interface
func (c TokenExchangeConfigurationProvider) TenancyOCID() (string, error) {
	claim, err := c.keyProvider.federationClient.GetClaim("tenant")
	if err != nil {
		return "", err
	}

	ocid, ok := claim.(string)
	if !ok {
		return "", ErrNonStringClaim
	}

	return ocid, nil
}

// UserOCID provides the required receiver for the ConfigurationProvider interface
func (c TokenExchangeConfigurationProvider) UserOCID() (string, error) {
	claim, err := c.keyProvider.federationClient.GetClaim("sub")
	if err != nil {
		return "", err
	}

	ocid, ok := claim.(string)
	if !ok {
		return "", ErrNonStringClaim
	}

	return ocid, nil
}

// KeyFingerprint provides the required receiver for the ConfigurationProvider
// interface
func (c TokenExchangeConfigurationProvider) KeyFingerprint() (string, error) {

	privateKey, err := c.keyProvider.PrivateRSAKey()
	if err != nil {
		return "", err
	}

	// Marshal the public key to DER format
	publicKeyDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
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

// Region providers the required receiver for the ConfigurationProvider interface
func (c TokenExchangeConfigurationProvider) Region() (string, error) {
	r := string(c.keyProvider.region)
	if r == "" {
		return "", ErrNoSuchClaim
	}

	return r, nil
}

// AuthType provides the required receiver for the ConfigurationProvider interface
func (c TokenExchangeConfigurationProvider) AuthType() (common.AuthConfig, error) {

	return common.AuthConfig{
		AuthType:         common.UnknownAuthenticationType,
		IsFromConfigFile: false,
	}, nil
}
