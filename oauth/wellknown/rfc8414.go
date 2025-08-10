package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// AuthServerMetadata represents the Authorization Server Metadata
// as defined in RFC 8414 Section 2
type AuthServerMetadata struct {
	// Required fields
	Issuer                 string   `json:"issuer"`
	ResponseTypesSupported []string `json:"response_types_supported"`

	// Optional fields
	AuthorizationEndpoint                              string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                                      string   `json:"token_endpoint,omitempty"`
	JwksUri                                            string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                               string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                                    []string `json:"scopes_supported,omitempty"`
	ResponseModesSupported                             []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                  []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported         []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ServiceDocumentation                               string   `json:"service_documentation,omitempty"`
	UiLocalesSupported                                 []string `json:"ui_locales_supported,omitempty"`
	OpPolicyUri                                        string   `json:"op_policy_uri,omitempty"`
	OpTosUri                                           string   `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                                 string   `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported             []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported    []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                              string   `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported                      []string `json:"code_challenge_methods_supported,omitempty"`
}

func (s *WellknownServer) HandleAuthorizationServer(w http.ResponseWriter, r *http.Request) {
	slog.Debug("HandleAuthorizationServer: Received request", "method", r.Method, "url", r.URL.String())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AuthServerMetadata{
		Issuer:                s.baseURL,
		TokenEndpoint:         s.baseURL + "/token",
		AuthorizationEndpoint: s.baseURL + "/authorize",
		ScopesSupported:       []string{"email"},
		ResponseTypesSupported: []string{
			"code",
		},
		ResponseModesSupported: []string{
			"query",
		},
		GrantTypesSupported: []string{
			"authorization_code",
		},
		CodeChallengeMethodsSupported: []string{
			"S256",
		},
		RegistrationEndpoint: s.baseURL + "/register",
	})
}
