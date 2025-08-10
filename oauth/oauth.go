package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/rcleveng/supabase-mcp-oauth/oauth/wellknown"

	"github.com/supabase-community/auth-go"
	"github.com/supabase-community/auth-go/types"
)

// Registry provides in-memory storage and HTTP handlers for dynamic client registration (RFC 7591).
type SupabaseMCPOAuthServer struct {
	baseURL        string
	supabaseURL    string
	supabaseKey    string
	authClient     auth.Client
	clientRegistry *OAuthClientRegistry
	wellknown      *wellknown.WellknownServer
}

// NewRegistry creates a new in-memory registry. baseURL should be the externally reachable
// base URL of this service (e.g. http://localhost:8080) and is used to build registration_client_uri values.
func NewSupabaseMCPOAuthServer(baseURL string, mcpResource string, supabaseURL string, supabaseKey string) (*SupabaseMCPOAuthServer, error) {
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid baseURL: %w", err)
	}
	baseURL = parsedBaseURL.String()

	if supabaseURL == "" {
		supabaseURL = os.Getenv("SUPABASE_URL")
	}
	if supabaseKey == "" {
		supabaseKey = os.Getenv("SUPABASE_KEY")
	}
	if supabaseURL == "" || supabaseKey == "" {
		return nil, fmt.Errorf("SUPABASE_URL and SUPABASE_KEY must be set")
	}

	projectRef := strings.Split(strings.Split(supabaseURL, "://")[1], ".")[0]
	authClient := auth.New(projectRef, supabaseKey)
	return &SupabaseMCPOAuthServer{
		baseURL:        baseURL,
		supabaseURL:    supabaseURL,
		supabaseKey:    supabaseKey,
		authClient:     authClient,
		clientRegistry: NewOAuthClientRegistry(baseURL),
		wellknown:      wellknown.NewWellknownServer(baseURL, mcpResource),
	}, nil
}

func (s *SupabaseMCPOAuthServer) handleOAuthLogin(w http.ResponseWriter, r *http.Request, provider types.Provider, authClient auth.Client) {
	queryParams := r.URL.Query()
	if queryParams.Get("client_id") == "" {
		slog.Error("handleOAuthLogin: client_id is required", "url", r.URL.String())
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	providerData, err := authClient.Authorize(types.AuthorizeRequest{
		Provider:   provider,
		RedirectTo: s.baseURL + "/callback?state=" + string(provider) + "&" + r.URL.RawQuery,
		Scopes:     "openid email profile",
		FlowType:   types.FlowPKCE,
	})
	if err != nil {
		slog.Error("handleOAuthLogin: Error signing in with Google", "url", r.URL.String(), "error", err)
		http.Error(w, fmt.Sprintf("Error signing in with Google: %s", err), http.StatusInternalServerError)
		return
	}

	slog.Debug("handleOAuthLogin: Provider data", "url", r.URL.String(), "providerData", providerData)
	// Add cookie to store the code verifier
	http.SetCookie(w, &http.Cookie{
		Name:  "code_verifier",
		Value: providerData.Verifier,
		Path:  "/",
	})

	http.Redirect(w, r, providerData.AuthorizationURL, http.StatusSeeOther)
}

func (s *SupabaseMCPOAuthServer) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	s.handleOAuthLogin(w, r, types.ProviderGoogle, s.authClient)
}

func (s *SupabaseMCPOAuthServer) handleMicrosoftLogin(w http.ResponseWriter, r *http.Request) {
	s.handleOAuthLogin(w, r, types.ProviderAzure, s.authClient)
}

func getCodeVerifier(w http.ResponseWriter, r *http.Request) string {
	codeVerifierCookie, err := r.Cookie("code_verifier")
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "code_verifier",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	return codeVerifierCookie.Value
}

// Handles the callback from the OAuth provider.
func (s *SupabaseMCPOAuthServer) handleCallback(w http.ResponseWriter, r *http.Request) {

	codeVerifier := getCodeVerifier(w, r)
	if codeVerifier == "" {
		http.Error(w, "code_verifier is required", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		slog.Error("handleCallback: code is required", "url", r.URL.String())
		http.Error(w, "code is required", http.StatusBadRequest)
		return
	}

	provider := r.URL.Query().Get("state")
	if provider == "" {
		http.Error(w, "state is required", http.StatusBadRequest)
		return
	}

	// log request
	slog.Debug("handleCallback: Received request", "method", r.Method, "code", code, "provider", provider, "codeVerifier", codeVerifier)

	details, err := s.authClient.Token(types.TokenRequest{
		GrantType:    "pkce",
		Code:         code,
		Provider:     provider,
		CodeVerifier: codeVerifier,
	})
	if err != nil {
		slog.Error("handleCallback: Error exchanging code for token", "url", r.URL.String(), "error", err)
		http.Error(w, fmt.Sprintf("Error exchanging code for token: %s", err), http.StatusInternalServerError)
		return
	}
	slog.Debug("handleCallback: Token response", "url", r.URL.String(), "details", details)
	redirectUri := r.URL.Query().Get("redirect_uri")
	if redirectUri == "" {
		slog.Error("handleCallback: redirect_uri is required", "url", r.URL.String())
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}
	redirectUrl, err := url.Parse(redirectUri)
	if err != nil {
		slog.Error("handleCallback: invalid redirect_uri", "url", r.URL.String(), "error", err)
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	params := redirectUrl.Query()
	params.Add("response_type", "code")
	client_id := r.URL.Query().Get("client_id")
	params.Add("client_id", client_id)
	params.Add("scope", r.URL.Query().Get("scope"))
	params.Add("code_challenge", r.URL.Query().Get("code_challenge"))
	params.Add("code_challenge_method", r.URL.Query().Get("code_challenge_method"))
	params.Add("state", r.URL.Query().Get("state"))
	params.Add("code", "CHANGEME-"+client_id)
	redirectUrl.RawQuery = params.Encode()
	slog.Debug("handleCallback: Redirecting to", "url", r.URL.String(), "redirectUrl", redirectUrl.String())
	http.Redirect(w, r, redirectUrl.String(), http.StatusSeeOther)
}

func (s *SupabaseMCPOAuthServer) RegisterHTTP(mux *http.ServeMux) {
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/callback", s.handleCallback)
	mux.HandleFunc("/login/google", s.handleGoogleLogin)
	mux.HandleFunc("/login/microsoft", s.handleMicrosoftLogin)
	mux.HandleFunc("/login/username_password", s.handleUsernamePasswordLogin)
	mux.HandleFunc("/token", s.handleToken)

	s.clientRegistry.RegisterHTTP(mux)
	s.wellknown.RegisterHTTP(mux)

}

func (s *SupabaseMCPOAuthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	// display success and return a access_token and refresh_token as JSON
	w.Header().Set("Content-Type", "application/json")
	// LOG request
	slog.Debug("handleToken: Received request", "method", r.Method, "url", r.URL.String())
	// print request body if POST
	if r.Method == "POST" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
			return
		}
		slog.Debug("handleToken: Request body", "url", r.URL.String(), "body", string(body))
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  "CHANGEME-access_token",
		"refresh_token": "CHANGEME-refresh_token",
		"token_type":    "Bearer",
		"expires_in":    3600,
	})
}

func (s *SupabaseMCPOAuthServer) handleUsernamePasswordLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Log the received username and password for debugging purposes
	slog.Debug("handleUsernamePasswordLogin: Received username/password login", "username", username, "password", password)

	// Here you would typically call a method on authClient to handle the username/password login
	// For example: authClient.SignInWithEmailPassword(username, password)
	// INSERT_YOUR_CODE
	response, err := s.authClient.SignInWithEmailPassword(username, password)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error signing in with username/password: %s", err), http.StatusInternalServerError)
		return
	}

	slog.Debug("handleUsernamePasswordLogin: Sign in with email/password response", "response", response)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func (s *SupabaseMCPOAuthServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		http.ServeFile(w, r, "oauth/login.html")
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed: "+r.Method, http.StatusMethodNotAllowed)
		return
	}
}
