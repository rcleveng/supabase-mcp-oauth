package wellknown

import "net/http"

type WellknownServer struct {
	baseURL     string
	mcpResource string
}

func NewWellknownServer(baseURL string, mcpResource string) *WellknownServer {
	return &WellknownServer{
		baseURL:     baseURL,
		mcpResource: mcpResource,
	}
}

func (s *WellknownServer) RegisterHTTP(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.HandleAuthorizationServer)
	mux.HandleFunc("/.well-known/oauth-authorization-server/", s.HandleAuthorizationServer)
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.HandleProtectedResource)
	mux.HandleFunc("/.well-known/oauth-protected-resource/", s.HandleProtectedResource)
	mux.HandleFunc("/.well-known/openid-configuration", s.HandleOidcDiscovery)
	mux.HandleFunc("/.well-known/openid-configuration/", s.HandleOidcDiscovery)
	mux.HandleFunc("/.well-known/openid-configuration/sse", s.HandleOidcDiscovery)
}
