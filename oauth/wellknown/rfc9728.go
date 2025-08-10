package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// ProtectedResourceMetadata represents the protected resource metadata
// as defined in RFC 9728 Section 2
type ProtectedResourceMetadata struct {
	Resource                              string   `json:"resource"`
	AuthorizationServers                  []string `json:"authorization_servers,omitempty"`
	JwksURI                               string   `json:"jwks_uri,omitempty"`
	ScopesSupported                       []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported                []string `json:"bearer_methods_supported,omitempty"`
	ResourceSigningAlgValuesSupported     []string `json:"resource_signing_alg_values_supported,omitempty"`
	ResourceName                          string   `json:"resource_name,omitempty"`
	ResourceDocumentation                 string   `json:"resource_documentation,omitempty"`
	ResourcePolicyURI                     string   `json:"resource_policy_uri,omitempty"`
	ResourceTosURI                        string   `json:"resource_tos_uri,omitempty"`
	TlsClientCertificateBoundAccessTokens bool     `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthorizationDetailsTypesSupported    []string `json:"authorization_details_types_supported,omitempty"`
	DpopSigningAlgValuesSupported         []string `json:"dpop_signing_alg_values_supported,omitempty"`
	DpopBoundAccessTokensRequired         bool     `json:"dpop_bound_access_tokens_required,omitempty"`
	SignedMetadata                        string   `json:"signed_metadata,omitempty"`
}

func (s *WellknownServer) HandleProtectedResource(w http.ResponseWriter, r *http.Request) {
	slog.Debug("HandleProtectedResource: Received request", "method", r.Method, "url", r.URL.String())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ProtectedResourceMetadata{
		Resource: s.mcpResource,
		AuthorizationServers: []string{
			s.baseURL,
		},
		ScopesSupported: []string{
			"email",
		},
		BearerMethodsSupported: []string{
			"Bearer",
		},
		ResourceName: "My MCP Protected Resource",
	})
}
