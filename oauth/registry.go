package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Implement the HTTP handlers for the dynamic client registration from https://datatracker.ietf.org/doc/html/rfc7591

// OAuthClientRegistry provides in-memory storage and HTTP handlers for dynamic client registration (RFC 7591).
type OAuthClientRegistry struct {
	mu                    sync.RWMutex
	baseURL               string
	clientIDToClient      map[string]ClientRegistrationResponse
	accessTokenToClientID map[string]string
}

// NewRegistry creates a new in-memory registry. baseURL should be the externally reachable
// base URL of this service (e.g. http://localhost:8080) and is used to build registration_client_uri values.
func NewOAuthClientRegistry(baseURL string) *OAuthClientRegistry {
	return &OAuthClientRegistry{
		baseURL:               strings.TrimRight(baseURL, "/"),
		clientIDToClient:      make(map[string]ClientRegistrationResponse),
		accessTokenToClientID: make(map[string]string),
	}
}

// RegisterHTTP registers the HTTP routes for client registration.
// - POST /register: Create a new client per RFC 7591 Section 3.2
// - GET  /register/{client_id}: Return the client metadata when authorized with the registration_access_token
func (r *OAuthClientRegistry) RegisterHTTP(mux *http.ServeMux) {
	mux.HandleFunc("/register", r.handleRegister)
	mux.HandleFunc("/register/", r.handleClientRead)
}

func (r *OAuthClientRegistry) handleRegister(w http.ResponseWriter, req *http.Request) {
	slog.Debug("handleRegister", "url", req.URL.String())
	if req.Method == http.MethodOptions {
		// Allow CORS middleware to append headers; simply acknowledge.
		w.WriteHeader(http.StatusNoContent)
		slog.Debug("handleRegister: Adding headers for CORS", "url", req.URL.String())
		return
	}
	if req.Method != http.MethodPost {
		slog.Warn("handleRegister: Method not allowed", "url", req.URL.String())
		http.Error(w, "method not allowed: "+req.Method, http.StatusMethodNotAllowed)
		return
	}

	var regReq ClientRegistrationRequest
	if err := json.NewDecoder(req.Body).Decode(&regReq); err != nil {
		slog.Warn("handleRegister: Invalid JSON", "url", req.URL.String())
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	if err := validateRegistrationRequest(regReq); err != nil {
		slog.Warn("handleRegister: Invalid request", "url", req.URL.String())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	clientID, err := randomString(32)
	if err != nil {
		slog.Error("handleRegister: Failed to generate client_id", "url", req.URL.String())
		http.Error(w, "failed to generate client_id", http.StatusInternalServerError)
		return
	}

	var clientSecret string
	// Generate client secret unless public client explicitly requested
	if !strings.EqualFold(strings.TrimSpace(regReq.TokenEndpointAuthMethod), "none") {
		clientSecret, err = randomString(48)
		if err != nil {
			slog.Error("handleRegister: Failed to generate client_secret", "url", req.URL.String())
			http.Error(w, "failed to generate client_secret", http.StatusInternalServerError)
			return
		}
	}

	issuedAt := time.Now().Unix()

	// Registration Access Token and Client URI (RFC 7591 Section 3.2)
	accessToken, err := randomString(48)
	if err != nil {
		slog.Error("handleRegister: Failed to generate registration_access_token", "url", req.URL.String())
		http.Error(w, "failed to generate registration_access_token", http.StatusInternalServerError)
		return
	}
	registrationClientURI := fmt.Sprintf("%s/register/%s", r.baseURL, clientID)

	resp := ClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        issuedAt,
		ClientSecretExpiresAt:   0, // 0 = does not expire
		RegistrationAccessToken: accessToken,
		RegistrationClientURI:   registrationClientURI,

		RedirectURIs:            regReq.RedirectURIs,
		TokenEndpointAuthMethod: regReq.TokenEndpointAuthMethod,
		GrantTypes:              regReq.GrantTypes,
		ResponseTypes:           regReq.ResponseTypes,
		ClientName:              regReq.ClientName,
		ClientURI:               regReq.ClientURI,
		LogoURI:                 regReq.LogoURI,
		Scope:                   regReq.Scope,
		TOSURI:                  regReq.TOSURI,
		PolicyURI:               regReq.PolicyURI,
		JWKSURI:                 regReq.JWKSURI,
		SoftwareID:              regReq.SoftwareID,
		SoftwareVersion:         regReq.SoftwareVersion,
		Contacts:                regReq.Contacts,
	}

	r.mu.Lock()
	r.clientIDToClient[clientID] = resp
	r.accessTokenToClientID[accessToken] = clientID
	r.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	slog.Debug("handleRegister: Client registered", "url", req.URL.String(), "client_id", clientID)
	_ = json.NewEncoder(w).Encode(resp)
}

func (r *OAuthClientRegistry) handleClientRead(w http.ResponseWriter, req *http.Request) {
	// Only allow GET for reading client info protected by the registration_access_token
	if req.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if req.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Expect path like /register/{client_id}
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "register" || parts[1] == "" {
		http.NotFound(w, req)
		return
	}
	clientID := parts[1]

	// Verify bearer token matches the registered client's registration_access_token
	token := extractBearerToken(req.Header.Get("Authorization"))
	if token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	r.mu.RLock()
	boundClientID, ok := r.accessTokenToClientID[token]
	if !ok || boundClientID != clientID {
		r.mu.RUnlock()
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	resp, ok := r.clientIDToClient[clientID]
	r.mu.RUnlock()
	if !ok {
		http.NotFound(w, req)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func validateRegistrationRequest(req ClientRegistrationRequest) error {
	// Minimal validation per RFC 7591: redirect_uris is generally required for web-based clients
	if len(req.RedirectURIs) == 0 {
		return errors.New("redirect_uris is required")
	}
	// Default grant_types/response_types if omitted are acceptable; server may infer.
	return nil
}

func randomString(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	// URL-safe, no padding to keep it concise
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func extractBearerToken(headerVal string) string {
	if headerVal == "" {
		return ""
	}
	parts := strings.SplitN(headerVal, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
