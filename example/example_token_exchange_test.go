package example

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/example/helpers"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

/* Examples for token exchange grant type require Identity Propagation Trust
/  to be configured on desired OCI Identity Domain
/  https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm
/
/ Examples use the following environment variables:
/
/    YOUR_TOKEN - A valid JWT issued by a provider registered in Identity Propagation Trust Configuration
/    OCI_ROOT_COMPARTMENT_ID - Root OCID of the OCI tenancy
/    OCI_DOMAIN_ENDPOINT - The URL for the Identity Domain issuing UPSTs (ex. https://idcs-xxxx-identity.oraclecloud.com)
/    OCI_CLIENT_ID - Client ID of the OAuth client application
/    OCI_CLIENT_SECRET - Client secret of the OAuth client application
/    OCI_REGION - A valid OCI region to query
*/

func ExampleTokenExchangeConfigurationProviderFromJWT() {
	upst := os.Getenv("YOUR_TOKEN") // a valid JWT

	provider, err := auth.TokenExchangeConfigurationProviderFromJWT(
		upst,
		os.Getenv("OCI_DOMAIN_ENDPOINT"),
		os.Getenv("OCI_CLIENT_ID"),
		os.Getenv("OCI_CLIENT_SECRET"),
		common.Region(os.Getenv("OCI_REGION")),
	)
	helpers.FatalIfError(err)

	key, err := provider.KeyID()
	log.Printf("key provider id: %v, %v\n", key, err)

	tenancyID := os.Getenv("OCI_ROOT_COMPARTMENT_ID")
	request := identity.ListAvailabilityDomainsRequest{
		CompartmentId: &tenancyID,
	}

	client, err := identity.NewIdentityClientWithConfigurationProvider(provider)

	r, err := client.ListAvailabilityDomains(context.Background(), request)
	helpers.FatalIfError(err)

	log.Printf("list of availablity domains: %v\n", r.Items)
	fmt.Println("Done")

	// Output:
	// Done
}
