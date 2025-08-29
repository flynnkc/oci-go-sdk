package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/oracle/oci-go-sdk/v65/common"
)

const (
	//	subTokenSpnego         string = "spnego"
	//	subTokenSaml           string = "saml"
	//	subTokenAwsCredential  string = "aws-credential"
	subTokenJwt            string = "jwt"
	tokenExchangeGrantType string = "grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
	requestedTokenType     string = "requested_token_type=urn:oci:token-type:oci-upst"
)

// TokenExchangeFunc is a variadic function that returns a JWT from a registered Identity
// Propagation Trust in string format and an error
type TokenExchangeFunc func(...interface{}) (string, error)

// tokenExchangeKeyProvider implements KeyProvider
type tokenExchangeKeyProvider struct {
	federationClient federationClient
	region           common.Region
}

func newTokenExchangeKeyProvider(domainUrl, clientId, clientSecret string,
	region common.Region, tokenFunc TokenExchangeFunc, args ...interface{}) (common.KeyProvider, error) {

	fc := &tokenExchangeFederationClient{
		args:             args,
		domainUrl:        domainUrl,
		refreshTokenFunc: tokenFunc,
		authCode: base64.StdEncoding.EncodeToString([]byte(
			clientId + ":" + clientSecret)),
	}

	kp := tokenExchangeKeyProvider{
		region:           region,
		federationClient: fc,
	}

	return kp, nil
}

// PrivateRSAKey provides the required receiver for the KeyProvider interface
func (t tokenExchangeKeyProvider) PrivateRSAKey() (*rsa.PrivateKey, error) {
	return t.federationClient.PrivateKey()
}

// KeyID provides the required receiver for the KeyProvider interface
func (t tokenExchangeKeyProvider) KeyID() (string, error) {
	securityToken, err := t.federationClient.SecurityToken()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("ST$%s", securityToken), nil
}

// tokenExchangeFederationClient implements federationClient
type tokenExchangeFederationClient struct {
	securityToken    securityToken
	privateKey       *rsa.PrivateKey
	refreshTokenFunc TokenExchangeFunc
	args             []interface{} // Direct access can cause concurrency issues
	domainUrl        string
	authCode         string
	mux              sync.Mutex
}

// UpdateArgs will update args variable in concurrency-safe manner
func (t *tokenExchangeFederationClient) UpdateArgs(args []interface{}) {
	t.mux.Lock()
	defer t.mux.Unlock()

	t.args = args
}

// PrivateKey receiver implements federationClient interface
func (t *tokenExchangeFederationClient) PrivateKey() (*rsa.PrivateKey, error) {
	if err := t.renewSecurityTokenIfNotValid(); err != nil {
		return nil, err
	}

	return t.privateKey, nil
}

// SecurityToken receiver implements federationClient interface
func (t *tokenExchangeFederationClient) SecurityToken() (string, error) {
	if err := t.renewSecurityTokenIfNotValid(); err != nil {
		return "", err
	}

	return t.securityToken.String(), nil
}

func (t *tokenExchangeFederationClient) GetClaim(key string) (interface{}, error) {
	return t.securityToken.GetClaim(key)
}

func (t *tokenExchangeFederationClient) renewSecurityTokenIfNotValid() error {
	if t.securityToken == nil || !t.securityToken.Valid() {
		t.mux.Lock()
		defer t.mux.Unlock()

		// Ensure token is not renewed by previously blocked operation
		if t.securityToken != nil && t.securityToken.Valid() {
			return nil
		}

		return t.renewSecurityToken()
	}

	return nil
}

func (t *tokenExchangeFederationClient) renewSecurityToken() error {

	// Generate private key using rand.Reader for getting secure randomness from
	// underlying operating system (e.g. /dev/urandom or getrandom())
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	publicKey, err := privateToPublicString(privateKey)
	if err != nil {
		return err
	}

	jwt, err := t.refreshTokenFunc(t.args...)
	if err != nil {
		return err
	}

	token, err := newTokenExchangeToken(jwt, publicKey, t.domainUrl, t.authCode)
	if err != nil {
		return err
	}

	t.privateKey = privateKey
	t.securityToken = token

	return nil
}

type tokenExchangeToken struct {
	token jwtToken
}

func newTokenExchangeToken(jwt, publicKey, host,
	authCode string) (tokenExchangeToken, error) {
	var t = tokenExchangeToken{}

	data := url.Values{
		"requested_token_type": {requestedTokenType},
		"grant_type":           {tokenExchangeGrantType},
		"public_key":           {publicKey},
		"subject_token_type":   {subTokenJwt},
		"subject_token":        {jwt},
	}

	request, err := http.NewRequest(http.MethodPost, host, strings.NewReader(data.Encode()))
	if err != nil {
		return t, err
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", "Basic "+authCode)

	client := &http.Client{}
	r, err := client.Do(request)
	if err != nil {
		return t, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return t, fmt.Errorf("invalid token endpoint response %s", r.Status)
	}

	var response map[string]interface{}
	if err = json.NewDecoder(r.Body).Decode(&response); err != nil {
		return t, fmt.Errorf("unable to unmarshal response: %s", err)
	}

	token, ok := response["token"].(string)
	if !ok {
		return t, fmt.Errorf("unable to unmarshal response: %s", err)
	}

	parsedToken, err := parseJwt(token)
	if err != nil {
		return t, err
	}

	t.token = *parsedToken

	return t, nil
}

// String implements fmt.Stringer
func (t tokenExchangeToken) String() string {
	return t.token.raw
}

// Valid implements the securityToken interface
func (t tokenExchangeToken) Valid() bool {
	return !t.token.expired()
}

// GetClaim implements the ClaimHolder interface
func (t tokenExchangeToken) GetClaim(key string) (interface{}, error) {

	// Per RFC7519 parsers should return only the lexically last member in the case
	// of duplicate claim names. We check payload first and return if claim found
	// and check header only if claim is not found in payload.
	if claim, ok := t.token.payload[key]; ok {
		return claim, nil
	}

	if claim, ok := t.token.header[key]; ok {
		return claim, nil
	}

	return nil, ErrNoSuchClaim
}

func privateToPublicString(pk *rsa.PrivateKey) (string, error) {
	publicBytes, err := x509.MarshalPKIXPublicKey(pk.Public())
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(publicBytes), nil
}
