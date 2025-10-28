package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
)

const (
	//	subTokenSpnego         string = "spnego"
	//	subTokenSaml           string = "saml"
	//	subTokenAwsCredential  string = "aws-credential"
	subTokenJwt            string        = "jwt"
	tokenExchangeGrantType string        = "urn:ietf:params:oauth:grant-type:token-exchange"
	requestedTokenType     string        = "urn:oci:token-type:oci-upst"
	rsaKeyBits             int           = 3072
	ctxTimeout             time.Duration = 10 * time.Second
	maxAttempts            int           = 5
	maxBackoff             time.Duration = 2 * time.Second
)

// TokenIssuer defines a type capable of retrieving JWT tokens for the issuing
// authorization server
type TokenIssuer interface {
	GetToken() (string, error)
}

// StaticTokenIssuer is a defined TokenIssuer that holds a static token
type StaticTokenIssuer struct {
	token string
}

// GetToken satisfies the TokenIssuer interface for StaticTokenIssuer by returning
// the token held by StaticTokenIssuer
func (s StaticTokenIssuer) GetToken() (string, error) {
	return s.token, nil
}

// tokenExchangeKeyProvider implements KeyProvider
type tokenExchangeKeyProvider struct {
	federationClient *tokenExchangeFederationClient
	region           common.Region
}

// newTokenExchangeKeyProvider assembles and returns a KeyProvider
func newTokenExchangeKeyProvider(domainUrl, clientId, clientSecret string,
	region string,
	tokenIssuer TokenIssuer) (*tokenExchangeKeyProvider, error) {

	if domainUrl == "" || clientId == "" || clientSecret == "" || region == "" ||
		tokenIssuer == nil {
		return nil, fmt.Errorf("invalid arguments to newTokenExchangeKeyProvider")
	}

	fc := &tokenExchangeFederationClient{
		httpClient:  &http.Client{Timeout: time.Second * 15},
		domainUrl:   domainUrl,
		tokenIssuer: tokenIssuer,
		authCode: base64.StdEncoding.EncodeToString([]byte(
			clientId + ":" + clientSecret)),
	}

	kp := tokenExchangeKeyProvider{
		region:           common.StringToRegion(region),
		federationClient: fc,
	}

	return &kp, nil
}

// PrivateRSAKey provides the required receiver for the KeyProvider interface
func (kp *tokenExchangeKeyProvider) PrivateRSAKey() (*rsa.PrivateKey, error) {
	return kp.federationClient.PrivateKey()
}

// KeyID provides the required receiver for the KeyProvider interface
func (kp *tokenExchangeKeyProvider) KeyID() (string, error) {
	securityToken, err := kp.federationClient.SecurityToken()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("ST$%s", securityToken), nil
}

// tokenExchangeFederationClient implements federationClient
type tokenExchangeFederationClient struct {
	httpClient    common.HTTPRequestDispatcher
	securityToken securityToken
	privateKey    *rsa.PrivateKey
	tokenIssuer   TokenIssuer
	domainUrl     string
	authCode      string
	mux           sync.Mutex
}

// UpdateHTTPClient updates the http.Client so clients with different transports,
// timeouts, etc. can be used. Locks mutex during update to prevent race conditions.
// Safe for concurrent use.
func (fc *tokenExchangeFederationClient) UpdateHTTPClient(c common.HTTPRequestDispatcher) error {
	if c == nil {
		return fmt.Errorf("invalid *http.Client")
	}

	fc.mux.Lock()
	defer fc.mux.Unlock()

	fc.httpClient = c

	return nil
}

// PrivateKey receiver implements federationClient interface. Safe for concurrent use.
func (fc *tokenExchangeFederationClient) PrivateKey() (*rsa.PrivateKey, error) {
	if err := fc.renewSecurityTokenIfNotValid(); err != nil {
		return nil, err
	}

	return fc.privateKey, nil
}

// SecurityToken receiver implements federationClient interface. Safe for concurrent
// use.
func (fc *tokenExchangeFederationClient) SecurityToken() (string, error) {
	if err := fc.renewSecurityTokenIfNotValid(); err != nil {
		return "", err
	}

	return fc.securityToken.String(), nil
}

// GetClaim returns claims embedded in the UPST
func (fc *tokenExchangeFederationClient) GetClaim(key string) (interface{}, error) {
	if err := fc.renewSecurityTokenIfNotValid(); err != nil {
		return nil, fmt.Errorf("unable to retrieve claim: %w", err)
	}

	return fc.securityToken.GetClaim(key)
}

// renewSecurityTokenIfNotValid checks if token is valid and initiates refresh if needed.
// Mutex is locked here if an operation is needed to prevent concurrency errors.
func (fc *tokenExchangeFederationClient) renewSecurityTokenIfNotValid() error {
	if fc.securityToken == nil || !fc.securityToken.Valid() {
		// Lock here to prevent renewSecurityToken from making surplus calls to the
		// authorization server and identity domain
		fc.mux.Lock()
		defer fc.mux.Unlock()

		// Ensure token is not renewed by previously blocked operation
		if fc.securityToken != nil && fc.securityToken.Valid() {
			return nil
		}

		return fc.renewSecurityToken()
	}

	return nil
}

// renewSecurityToken initiates renewal of the UPST returned by the
// tokenExchangeFederationClient. Should only be called by renewSecurityTokenIfNotValid.
// Rotates RSA key and updates federation client with fresh UPST and private key.
func (fc *tokenExchangeFederationClient) renewSecurityToken() (err error) {
	var jwt string

	// Since we are running arbitrary code, we catch panics and return the cause
	// as an error
	func() {
		// Scope recover around caller-provided code
		common.Logf("attempting to retrieve token from issuer")
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic occurred during token renewal: %v", r)
			}
		}()

		// Get a fresh JWT from the issuer
		jwt, err = fc.tokenIssuer.GetToken()

	}()

	if err != nil {
		return fmt.Errorf("unable to refresh JWT: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return fmt.Errorf("unable to generate RSA key: %w", err)
	}

	publicKey, err := privateToPublicDERBase64(privateKey)
	if err != nil {
		return fmt.Errorf("unable to derive public key: %w", err)
	}

	securityToken, err := newTokenExchangeToken(fc.httpClient, jwt, publicKey,
		fc.domainUrl, fc.authCode)
	if err != nil {
		return fmt.Errorf("unable to exchange for UPST: %w", err)
	}

	// privateKey and securityToken ONLY updated here while under lock from renewSecurityTokenIfNotValid
	fc.privateKey = privateKey
	fc.securityToken = securityToken

	return nil
}

// tokenExchangeToken contains token and any related fields
type tokenExchangeToken struct {
	token jwtToken
}

// newTokenExchangeToken assembles and returns a tokenExchangeToken issued by OCI
func newTokenExchangeToken(client common.HTTPRequestDispatcher, jwt, publicKey string,
	host, authCode string) (tokenExchangeToken, error) {
	var t tokenExchangeToken
	var err error

	form := url.Values{
		"requested_token_type": {requestedTokenType},
		"grant_type":           {tokenExchangeGrantType},
		"public_key":           {publicKey},
		"subject_token_type":   {subTokenJwt},
		"subject_token":        {jwt},
	}.Encode()

	tokenURL, err := buildTokenURL(host)
	if err != nil {
		return t, fmt.Errorf("unable to build token endpoint url: %w", err)
	}

	// Retry and backoff
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	backoff := 100 * time.Millisecond
	var resp *http.Response
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		common.Logf("attempt %d to retrieve UPST (max attempts %d)", attempt,
			maxAttempts)

		ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
			strings.NewReader(form))
		if err != nil {
			cancel()
			return t, err
		}

		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Authorization", "Basic "+authCode)
		request.Header.Set("Accept", "application/json")

		resp, err = client.Do(request)
		if err == nil && resp.StatusCode == http.StatusOK {
			cancel()
			break
		}
		// Skip last sleep on max attempts
		if attempt == maxAttempts {
			cancel()
			break
		}
		// Do not retry response codes
		if resp != nil && (resp.StatusCode == http.StatusBadRequest ||
			resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusNotFound) {
			drainResponseBody(resp)
			cancel()
			break
		}

		if resp != nil {
			common.Logf("invalid response from domain: %d", resp.Status)
			drainResponseBody(resp)
		} else {
			common.Logf("invalid response from domain: %v", err)
		}

		jitter := time.Duration(r.Int63n(int64(backoff / 2)))
		sleep := backoff + jitter
		time.Sleep(sleep)

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}

		cancel()
	}

	if resp == nil {
		return t, fmt.Errorf("no response from domain: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return t, fmt.Errorf("invalid token endpoint response %s", resp.Status)
	}

	type tokenResponse struct {
		Token string `json:"token"`
	}

	var responseBody tokenResponse
	if err = json.NewDecoder(resp.Body).Decode(&responseBody); err != nil {
		return t, fmt.Errorf("unable to unmarshal response: %w", err)
	}

	if responseBody.Token == "" {
		return t, fmt.Errorf("token not found in response")
	}

	parsedToken, err := parseJwt(responseBody.Token)
	if err != nil {
		return t, fmt.Errorf("unable to parse token: %w", err)
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

// privateToPublicDERBase64 takes an RSA Private Key and returns a public key in DER format
func privateToPublicDERBase64(pk *rsa.PrivateKey) (string, error) {
	publicBytes, err := x509.MarshalPKIXPublicKey(pk.Public())
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(publicBytes), nil
}

func drainResponseBody(response *http.Response) {
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

func buildTokenURL(host string) (string, error) {
	base := strings.TrimSpace(host)
	if base == "" {
		return "", fmt.Errorf("empty host")
	}
	// Default to https if no scheme provided
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid host base URL: %q", host)
	}

	u.Path, err = url.JoinPath(u.EscapedPath(), "oauth2", "v1", "token")
	if err != nil {
		return "", err
	}
	return u.String(), nil

}
