package wellknown

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/rcleveng/supabase-mcp-oauth/oauth/wrappedjwt"
)

type WellknownServer struct {
	baseURL     string
	mcpResource string
	keyManager  *wrappedjwt.KeyManager
}

func NewWellknownServer(baseURL string, mcpResource string, keyManager *wrappedjwt.KeyManager) *WellknownServer {
	return &WellknownServer{
		baseURL:     baseURL,
		mcpResource: mcpResource,
		keyManager:  keyManager,
	}
}

func (s *WellknownServer) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	slog.Debug("HandleJWKS: Received request", "method", r.Method, "url", r.URL.String())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	keysData, err := s.keyManager.ExportPublicKeyJWKs()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error exporting public keys: %s", err), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(keysData)
}

func (s *WellknownServer) RegisterHTTP(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.HandleAuthorizationServer)
	mux.HandleFunc("/.well-known/oauth-authorization-server/", s.HandleAuthorizationServer)
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.HandleProtectedResource)
	mux.HandleFunc("/.well-known/oauth-protected-resource/", s.HandleProtectedResource)
	mux.HandleFunc("/.well-known/openid-configuration", s.HandleOidcDiscovery)
	mux.HandleFunc("/.well-known/openid-configuration/", s.HandleOidcDiscovery)
	mux.HandleFunc("/.well-known/openid-configuration/sse", s.HandleOidcDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", s.HandleJWKS)
}
