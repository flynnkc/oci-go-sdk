package auth

import (
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/common"
)

// ConfigurationProviderWithHTTPClient is a configuration provider that exposes claims
// and allows injecting a custom *http.Client for outbound requests.
type ConfigurationProviderWithHTTPClient interface {
	ConfigurationProviderWithClaimAccess
	SetHTTPClient(*http.Client) error
}

// TokenExchangeConfigurationProvider provides OCI configuration via token exchange,
// exposing claims and supporting a custom HTTP client.
type TokenExchangeConfigurationProvider struct {
	keyProvider *tokenExchangeKeyProvider
}

// TokenExchangeConfigurationProviderFromIssuer creates a Configuration Provider from a
// function provided to retrieve a JWT from an identity provider
func TokenExchangeConfigurationProviderFromIssuer(tokenIssuer TokenIssuer,
	domainUrl, clientId, clientSecret string,
	region string) (ConfigurationProviderWithHTTPClient, error) {

	kp, err := newTokenExchangeKeyProvider(domainUrl, clientId, clientSecret,
		region, tokenIssuer)
	if err != nil {
		common.Logf("unable to create configuration provider: %s", err)
		return nil, err
	}

	// Check for errors by trying to get token
	_, err = kp.KeyID()
	if err != nil {
		return nil, err
	}

	return &TokenExchangeConfigurationProvider{
		keyProvider: kp,
	}, nil
}

// TokenExchangeConfigurationProviderFromJWT returns a new configuration provider
// from a static User Principal Security Token (UPST)
func TokenExchangeConfigurationProviderFromJWT(jwt, domainEndpoint, clientId, clientSecret string,
	region string) (ConfigurationProviderWithHTTPClient, error) {

	issuer := StaticTokenIssuer{token: jwt}

	return TokenExchangeConfigurationProviderFromIssuer(issuer, domainEndpoint, clientId,
		clientSecret, region)
}

func (c TokenExchangeConfigurationProvider) GetClaim(key string) (interface{}, error) {
	return c.keyProvider.federationClient.GetClaim(key)
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
	der, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return "", err
	}

	sum := md5.Sum(der)
	hexStr := hex.EncodeToString(sum[:]) // 32 hex chars

	var sb strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(hexStr[i : i+2])
	}
	return sb.String(), nil

}

// Region provides the required receiver for the ConfigurationProvider interface
func (c TokenExchangeConfigurationProvider) Region() (string, error) {
	r := string(c.keyProvider.region)
	if r == "" {
		return "", fmt.Errorf("no region assigned")
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

// SetHTTPClient allows a provided http.Client to be used so timeouts, transport
// and other features can be set as required
func (c *TokenExchangeConfigurationProvider) SetHTTPClient(h *http.Client) error {
	return c.keyProvider.federationClient.UpdateHTTPClient(h)
}
