package example

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/example/helpers"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// Examples for token exchange grant type require Identity Propagation Trust
//  to be configured on desired OCI Identity Domain. Documentation for setting up a
//  Identity Propagation Trust can be found at the following location:
//  https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm
//
// Examples use the following environment variables:
//
//  Domain Variables (Required):
//    OCI_DOMAIN_URL - The URL for the Identity Domain issuing
//        User Principal Session Tokens (UPST) (ex. https://idcs-xxxx-identity.oraclecloud.com)
//    OCI_CLIENT_ID - Client ID of the OAuth client application
//    OCI_CLIENT_SECRET - Client secret of the OAuth client application
//    OCI_REGION - A valid OCI region to query
//
//  OCI Identity Client variables (Required):
//    OCI_ROOT_COMPARTMENT_ID - Root OCID of the OCI tenancy
//
//  Token Exchange from Configuration Provider From JWT Variables:
//    YOUR_TOKEN - A valid JWT issued by a provider registered in Identity Propagation Trust Configuration
//
//  Token Exchange from Function Variables:
//    ISSUER_ENDPOINT - Token issuer endpoint for authorization server
//    ISSUER_ID - Client ID for client credentials flow
//    ISSUER_SECRET - Client secret for client credentials flow

// ExampleTokenExchangeConfigurationProviderFromJWT demonstrates exchanging a JWT for
// a UPST and calling the Identity client
func ExampleTokenExchangeConfigurationProviderFromJWT() {
	// YOUR_TOKEN MUST be a valid JWT issued by a registered Identity Propagation Trust
	jwt := os.Getenv("YOUR_TOKEN")

	provider, err := auth.TokenExchangeConfigurationProviderFromJWT(
		jwt,
		os.Getenv("OCI_DOMAIN_URL"),
		os.Getenv("OCI_CLIENT_ID"),
		os.Getenv("OCI_CLIENT_SECRET"),
		os.Getenv("OCI_REGION"),
	)
	helpers.FatalIfError(err)

	tenancyID := os.Getenv("OCI_ROOT_COMPARTMENT_ID")
	request := identity.ListAvailabilityDomainsRequest{
		CompartmentId: &tenancyID,
	}

	client, err := identity.NewIdentityClientWithConfigurationProvider(provider)
	helpers.FatalIfError(err)

	r, err := client.ListAvailabilityDomains(context.Background(), request)
	helpers.FatalIfError(err)

	log.Printf("List of availability domains: %v\n", r.Items)
	fmt.Println("Done")

	// Output:
	// Done
}

// ExampleTokenExchangeConfigurationProviderFromIssuer demonstrates using a function to
// get and refresh UPSTs by calling the JWT issuer
func ExampleTokenExchangeConfigurationProviderFromIssuer() {
	// Optional HTTP Client
	httpClient := &http.Client{Timeout: time.Second * 10}

	// ExampleIssuer defined below that complies with the TokenIssuer interface. This
	// is what will issue the JWTs we exchange for OCI UPSTs.
	issuer := &ExampleIssuer{
		IssuerEndpoint: os.Getenv("ISSUER_ENDPOINT"),
		ClientId:       os.Getenv("ISSUER_ID"),
		ClientSecret:   os.Getenv("ISSUER_SECRET"),
		Method:         http.MethodPost,
		HttpClient:     httpClient,
	}

	// The provider consumes the TokenIssuer and exchanges the issued JWT(s) for UPST(s)
	provider, err := auth.TokenExchangeConfigurationProviderFromIssuer(
		issuer, // Gets and refreshes JWT tokens
		os.Getenv("OCI_DOMAIN_URL"),
		os.Getenv("OCI_CLIENT_ID"),
		os.Getenv("OCI_CLIENT_SECRET"),
		os.Getenv("OCI_REGION"))
	helpers.FatalIfError(err)

	// Optional: A default client is provided
	provider.SetHTTPClient(httpClient)

	tenancyID := os.Getenv("OCI_ROOT_COMPARTMENT_ID")
	request := identity.ListAvailabilityDomainsRequest{
		CompartmentId: &tenancyID,
	}

	client, err := identity.NewIdentityClientWithConfigurationProvider(provider)
	helpers.FatalIfError(err)

	r, err := client.ListAvailabilityDomains(context.Background(), request)
	helpers.FatalIfError(err)

	log.Printf("List of availability domains: %v\n", r.Items)
	fmt.Println("Done")

	// Output:
	// Done
}

// ExampleIssuer satisfies the TokenIssuer interface. Defining one's own struct will
// allow for storage of as much or as little data as needed to get JWTs from the
// authorization server. This allows for flexibility in defining how to retrieve JWTs
// and any required data or logic.
type ExampleIssuer struct {
	IssuerEndpoint string       // Token endpoint of example authorization server
	ClientId       string       // Required for client credentials flow
	ClientSecret   string       // Required for client credentials flow
	Method         string       // Expected HTTP method for request
	HttpClient     *http.Client // Client to use for request
}

// GetToken allows the ExampleIssuer to satisfy the TokenIssuer interface. This receiver
// method will be called to get and refresh JWTs. Anything can be substituted in this
// method as long as it returns a valid JWT in string form and an error.
func (e *ExampleIssuer) GetToken() (string, error) {

	// Required values for example request as defined by authorization server
	data := url.Values{
		"grant_type": {"client_credentials"}, // Client credentials flow
		"scope":      {"token_exchange"},     // Custom scope
	}

	request, err := http.NewRequest(e.Method, e.IssuerEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	// Basic authentication requires base64 encoding
	authHeader := fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(
		e.ClientId+":"+e.ClientSecret)))

	// Headers required by example authorization server
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", authHeader)

	response, err := e.HttpClient.Do(request)
	if err != nil {
		return "", err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-200 status code returned: %v", response.StatusCode)
	}

	var body map[string]interface{}
	if err = json.NewDecoder(response.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("unable to unmarshal response: %s", err)
	}

	token, ok := body["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("unable to retrieve access token")
	}

	return token, nil
}
