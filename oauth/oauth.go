package oauth

import (
	"crypto/rand"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rcleveng/supabase-mcp-oauth/oauth/wellknown"
	"github.com/rcleveng/supabase-mcp-oauth/oauth/wrappedjwt"

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
	keyManager     *wrappedjwt.KeyManager
	codes          *CodeServer
}

// NewRegistry creates a new in-memory registry. baseURL should be the externally reachable
// base URL of this service (e.g. http://localhost:8080) and is used to build registration_client_uri values.
func NewSupabaseMCPOAuthServer(baseURL string, mcpResource string, supabaseURL string, supabaseKey string, keyManager *wrappedjwt.KeyManager) (*SupabaseMCPOAuthServer, error) {
	// TODO - If we need another parameter, switch to options pattern
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
	codes, err := NewCodeServer("memory", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create code server: %w", err)
	}
	return &SupabaseMCPOAuthServer{
		baseURL:        baseURL,
		supabaseURL:    supabaseURL,
		supabaseKey:    supabaseKey,
		authClient:     authClient,
		clientRegistry: NewOAuthClientRegistry(baseURL),
		wellknown:      wellknown.NewWellknownServer(baseURL, mcpResource, keyManager),
		keyManager:     keyManager,
		codes:          codes,
	}, nil
}

func (s *SupabaseMCPOAuthServer) handleOAuthLogin(w http.ResponseWriter, r *http.Request, provider types.Provider, authClient auth.Client) {
	queryParams := r.URL.Query()
	if queryParams.Get("client_id") == "" {
		slog.Error("handleOAuthLogin: client_id is required", "url", r.URL.String())
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	// Use the Supabase auth client flow here to authorize the user.
	providerData, err := authClient.Authorize(types.AuthorizeRequest{
		Provider:   provider,
		RedirectTo: s.baseURL + "/callback?state=" + string(provider) + "&" + r.URL.RawQuery,
		Scopes:     "openid email profile",
		FlowType:   types.FlowPKCE,
	})
	if err != nil {
		slog.Error("handleOAuthLogin: Error authorizing with provider", "url", r.URL.String(), "error", err, "provider", string(provider))
		http.Error(w, fmt.Sprintf("Error authorizing with provider: %s", err), http.StatusInternalServerError)
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

	// TODO - Either don't exchange the code here, or store it in the database along with a
	// new code we give to the client that is bound with the client id.
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

	// register the code with the code server
	clientCode := rand.Text()
	err = s.codes.RegisterCode(Code{
		ID:           clientCode,
		Code:         code,
		ClientID:     r.URL.Query().Get("client_id"),
		CodeVerifier: codeVerifier,
		ExpiresAt:    time.Now().Add(10 * time.Minute),
		AccessToken:  details.AccessToken,
		RefreshToken: details.RefreshToken,
		UserID:       details.User.ID.String(),
		Email:        details.User.Email,
	})
	if err != nil {
		slog.Error("handleCallback: Error registering code", "url", r.URL.String(), "error", err)
		http.Error(w, fmt.Sprintf("Error registering code: %s", err), http.StatusInternalServerError)
		return
	}

	// Send redirect to the client.
	params := redirectUrl.Query()
	params.Add("response_type", "code")
	client_id := r.URL.Query().Get("client_id")
	params.Add("client_id", client_id)
	params.Add("scope", r.URL.Query().Get("scope"))
	params.Add("code_challenge", r.URL.Query().Get("code_challenge"))
	params.Add("code_challenge_method", r.URL.Query().Get("code_challenge_method"))
	params.Add("state", r.URL.Query().Get("state"))
	// be sure to send the client code and not the code from the provider.
	params.Add("code", clientCode)
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
	if r.Method != "POST" {
		slog.Error("handleToken: Method not allowed", "url", r.URL.String(), "method", r.Method)
		http.Error(w, "Method not allowed: "+r.Method, http.StatusMethodNotAllowed)
		return
	}
	// Get form data
	if grant_type := r.FormValue("grant_type"); grant_type != "authorization_code" {
		slog.Error("handleToken: grant_type must be authorization_code", "url", r.URL.String(), "grant_type", grant_type)
		http.Error(w, "grant_type must be authorization_code", http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	if code == "" {
		slog.Error("handleToken: code is required", "url", r.URL.String())
		http.Error(w, "code is required", http.StatusBadRequest)
		return
	}
	clientID := r.FormValue("client_id")
	if clientID == "" {
		slog.Error("handleToken: client_id is required", "url", r.URL.String())
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	codeVerifier := r.FormValue("code_verifier")
	if codeVerifier == "" {
		slog.Error("handleToken: code_verifier is required", "url", r.URL.String())
		http.Error(w, "code_verifier is required", http.StatusBadRequest)
		return
	}
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI == "" {
		slog.Error("handleToken: redirect_uri is required", "url", r.URL.String())
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}

	codeDetails, err := s.codes.FindCode(code, clientID, codeVerifier)
	if err != nil {
		slog.Error("handleToken: Error finding code", "url", r.URL.String(), "error", err)
		http.Error(w, fmt.Sprintf("Error finding code: %s", err), http.StatusInternalServerError)
		return
	}

	wrapper := wrappedjwt.NewUpstreamTokenWrapper(s.keyManager)
	wrappedAccessToken, err := wrapper.Wrap(wrappedjwt.WrapRequest{
		Token: codeDetails.AccessToken,
		Issuer:           s.baseURL,
		Subject:          codeDetails.UserID,
		Audience:         clientID,
		AdditionalClaims: map[string]any{},
	})
	if err != nil {
		fmt.Println("Error wrapping access token", err)
		slog.Error("handleToken: Error wrapping access token", "url", r.URL.String(), "error", err)
		http.Error(w, fmt.Sprintf("Error wrapping access token: %s", err), http.StatusInternalServerError)
		return
	}
	wrappedRefreshToken, err := wrapper.Wrap(wrappedjwt.WrapRequest{
		Token: codeDetails.RefreshToken,
		Issuer:           s.baseURL,
		Subject:          codeDetails.UserID,
		Audience:         clientID,
		AdditionalClaims: map[string]any{},
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Error wrapping refresh token: %s", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":  wrappedAccessToken,
		"refresh_token": wrappedRefreshToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
	})

	// redirect to the redirectURI
	http.Redirect(w, r, redirectURI, http.StatusSeeOther)
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

//go:embed login.html
var loginHTML embed.FS

func (s *SupabaseMCPOAuthServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// http.ServeContent(w, r, "login.html", time.Now(), strings.NewReader(loginHTML))
		// INSERT_YOUR_CODE
		http.ServeFileFS(w, r, loginHTML, "login.html")
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed: "+r.Method, http.StatusMethodNotAllowed)
		return
	}
}
