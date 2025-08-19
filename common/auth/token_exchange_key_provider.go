package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"

	"github.com/oracle/oci-go-sdk/v65/common"
)

const (
	subTokenSpnego        TokenType = "spnego"
	subTokenJwt           TokenType = "jwt"
	subTokenSaml          TokenType = "saml"
	subTokenAwsCredential TokenType = "aws-credential"
)

type TokenType string

type TokenExchangeKeyProvider struct {
	GetJWT     func(...interface{}) (*jwtToken, error)
	region     string
	privateKey *rsa.PrivateKey
	token      *jwtToken
	sync.Mutex
}

func (t *TokenExchangeKeyProvider) PrivateRSAKey() (*rsa.PrivateKey, error) {
	return t.privateKey, nil
}

func (t *TokenExchangeKeyProvider) KeyID() (string, error) {
	return fmt.Sprintf("ST$%s", t.token.raw), nil
}

func (t *TokenExchangeKeyProvider) RefreshRSAKey() error {
	t.Lock()
	defer t.Unlock()

	// Generate private key using rand.Reader for getting secure randomness from
	// underlying operating system (e.g. /dev/urandom or getrandom())
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	t.privateKey = privateKey
	return nil
}

func staticKeyProvider(jwt string) (common.KeyProvider, error) {
	token, err := parseJwt(jwt)
	if err != nil {
		return nil, err
	}

	kp := &TokenExchangeKeyProvider{
		GetJWT: func(i ...interface{}) (*jwtToken, error) {
			return token, nil
		},
		token: token,
	}

	// Generate rsa.PrivateKey
	err = kp.RefreshRSAKey()
	if err != nil {
		return nil, err
	}

	return kp, nil
}
