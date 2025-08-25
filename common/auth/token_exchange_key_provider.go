package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
)

const (
	subTokenSpnego        TokenType = "spnego"
	subTokenJwt           TokenType = "jwt"
	subTokenSaml          TokenType = "saml"
	subTokenAwsCredential TokenType = "aws-credential"
)

type TokenType string

// tokenExchangeKeyProvider implements KeyProvider
type tokenExchangeKeyProvider struct {
	federationClient federationClient
	region           string
	privateKey       *rsa.PrivateKey
}

// PrivateRSAKey provides the required receiver for the KeyProvider interface
func (t *tokenExchangeKeyProvider) PrivateRSAKey() (*rsa.PrivateKey, error) {
	return t.privateKey, nil
}

// KeyID provides the required receiver for the KeyProvider interface
func (t *tokenExchangeKeyProvider) KeyID() (string, error) {
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
	refreshTokenFunc func(...interface{}) (string, error)
	args             []interface{}
	mux              sync.Mutex
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

func (t *tokenExchangeFederationClient) renewSecurityTokenIfNotValid() error {
	if t.securityToken == nil || !t.securityToken.Valid() {
		return t.renewSecurityToken()
	}

	return nil
}

func (t *tokenExchangeFederationClient) renewSecurityToken() error {
	t.mux.Lock()
	defer t.mux.Unlock()

	// Generate private key using rand.Reader for getting secure randomness from
	// underlying operating system (e.g. /dev/urandom or getrandom())
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	jwt, err := t.refreshTokenFunc(t.args...)
	if err != nil {
		return err
	}

	token, err := newTokenExchangeToken(jwt, privateKey)
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

func newTokenExchangeToken(jwt string,
	privateKey *rsa.PrivateKey) (tokenExchangeToken, error) {

	var token = tokenExchangeToken{}

	// Need to insert things here

	return token, nil
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
