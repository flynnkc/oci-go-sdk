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

	"github.com/oracle/oci-go-sdk/v65/common"
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
//    OCI_DOMAIN_ENDPOINT - The URL for the Identity Domain issuing
//        User Principal Session Tokens (UPST) (ex. https://idcs-xxxx-identity.oraclecloud.com)
//    OCI_CLIENT_ID - Client ID of the OAuth client application
//    OCI_CLIENT_SECRET - Client secret of the OAuth client application
//    OCI_REGION - A valid OCI region to query
//
//  OCI Identity Client varibles (Required):
//    OCI_ROOT_COMPARTMENT_ID - Root OCID of the OCI tenancy
//
//  Token Exchange from Configuration Provider From JWT Variables:
//    YOUR_TOKEN - A valid JWT issued by a provider registered in Identity Propagation Trust Configuration
//
//  Token Exchange from Function Variables:
//    ISSUER_ENDPOINT - Token issuer endpoint for authorization server
//    ISSUER_ID - Client ID for client credentials flow
//    ISSUER_SECRET - Client secret for client credentials flow

// ExampleTokenExchangeConfigurationProviderFromJWT demonstrates exchanging a JWT for a UPST and calling the Identity client
func ExampleTokenExchangeConfigurationProviderFromJWT() {
	// YOUR_TOKEN MUST be a valid JWT issued by a registered Identity Propagation Trust
	upst := os.Getenv("YOUR_TOKEN")

	provider, err := auth.TokenExchangeConfigurationProviderFromJWT(
		upst,
		os.Getenv("OCI_DOMAIN_ENDPOINT"),
		os.Getenv("OCI_CLIENT_ID"),
		os.Getenv("OCI_CLIENT_SECRET"),
		common.Region(os.Getenv("OCI_REGION")),
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

// ExampleTokenExchangeConfigurationProviderFromFunc demonstrates using a function to get and refresh UPSTs by calling the JWT issuer
func ExampleTokenExchangeConfigurationProviderFromFunc() {
	// In this example, TokenExchangeFunc requires the issuer Client ID and issuer
	// Client Secret to be passed for OAuth2 Client Credentials flow
	args := []interface{}{os.Getenv("ISSUER_ID"), os.Getenv("ISSUER_SECRET")}

	provider, err := auth.TokenExchangeConfigurationProviderFromFunc(
		os.Getenv("OCI_DOMAIN_ENDPOINT"),
		os.Getenv("OCI_CLIENT_ID"),
		os.Getenv("OCI_CLIENT_SECRET"),
		common.Region(os.Getenv("OCI_REGION")),
		getJWTFromIssuer, // TokenExchangeFunc renews JWT tokens with issuer
		args)             // Args to be consumed by TokenExchangeFunc
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

// getJWTFromIssuer satisfies the TokenExchangeFunc interface and can be passed
// to TokenExchangeConfigurationProviderFromFunc for retrieving JWTs from an issuer
func getJWTFromIssuer(args []interface{}) (string, error) {
	clientId, ok := args[0].(string) // Client ID
	if !ok {
		return "", fmt.Errorf("invalid issuer client id")
	}

	clientSecret, ok := args[1].(string) // Client Secret
	if !ok {
		return "", fmt.Errorf("invalid issuer client secret")
	}

	data := url.Values{
		"grant_type": {"client_credentials"}, // Client credentials flow
		"scope":      {"token_exchange"},     // Custom scope
	}
	method := "POST"
	issuerURL := os.Getenv("ISSUER_ENDPOINT")

	request, err := http.NewRequest(method, issuerURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	// Basic authentication requires base64 encoding
	authHeader := fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(
		clientId+":"+clientSecret)))

	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	} else if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-200 status code returned: %v", response.StatusCode)
	}

	defer response.Body.Close()

	var body map[string]interface{}
	if err = json.NewDecoder(response.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("unable to unmarshal response: %s", err)
	}

	token, ok := body["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("unable to retrive access token: %s", err)
	}

	return token, nil
}
