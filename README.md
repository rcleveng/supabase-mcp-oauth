# Supabase MCP OAuth Server

A complete OAuth 2.0 Authorization Server and Resource Server implementation specifically designed for securing MCP (Model Context Protocol) servers. This project integrates with Supabase Auth to provide enterprise-grade authentication and authorization for MCP-based applications.

## Features

- **OAuth 2.0**: Full implementation of OAuth 2.0 authorization server with PKCE support
- **Dynamic Client Registration**: RFC 7591 compliant client registration endpoint
- **Multiple Authentication Providers**: 
  - Google OAuth
  - Microsoft Azure OAuth
  - Username/Password (Supabase Auth)
- **Well-known Endpoints**: Standards-compliant discovery endpoints for OAuth2 and OpenID Connect
- **CORS Support**: Configurable CORS handling for browser-based MCP clients which use fetch()
- **Supabase Integration**: Uses Supabase Auth backend and PostgreSQL

## Architecture

This server acts as both:
- **Authorization Server**: Issues access tokens after user authentication
- **Resource Server**: Protects MCP resources using issued tokens

## Quick Start

### Prerequisites

- Go 1.23 or later
- Supabase project with Auth enabled
- Environment variables configured

### Installation

1. Clone the repository:
```bash
git clone https://github.com/rcleveng/supabase-mcp-oauth.git
cd supabase-mcp-oauth
```

2. Install dependencies:
```bash
go mod download
```

3. Create a `.env` file:
```bash
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-key
BASE_URL=http://localhost:8080
MCP_RESOURCE=your-mcp-resource-identifier
```

4. Create your server.  Example:
```go
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/rcleveng/supabase-mcp-oauth/mcp"
	"github.com/rcleveng/supabase-mcp-oauth/oauth"
	"github.com/rcleveng/supabase-mcp-oauth/tools"

	"github.com/joho/godotenv"
)

var (
	host        = flag.String("host", "localhost", "host to listen on")
	port        = flag.String("port", "8080", "port to listen on")
	serverURL   = flag.String("server-url", "", "server url to listen on")
	mcpResource = flag.String("mcp-resource", "", "mcp resource to listen on")
	supabaseURL = flag.String("supabase-url", os.Getenv("SUPABASE_URL"), "supabase url to listen on")
	supabaseKey = flag.String("supabase-key", os.Getenv("SUPABASE_KEY"), "supabase key to listen on")
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	if *supabaseURL == "" || *supabaseKey == "" {
		fmt.Println("SUPABASE_URL and SUPABASE_KEY must be set")
		return
	}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "This program runs MCP servers over SSE HTTP.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEndpoints:\n")
		fmt.Fprintf(os.Stderr, "  /sse     - Default SSE endpoint\n")
		os.Exit(1)
	}
	flag.Parse()

	hostPort := fmt.Sprintf("%s:%s", *host, *port)
	if *serverURL == "" {
		*serverURL = "http://" + hostPort
	}
	if *mcpResource == "" {
		*mcpResource = *serverURL
	}
	mux := http.NewServeMux()

	// Create the MCP OAuth server and register the endpoints.
	keyManager, err := wrappedjwt.NewKeyManager("memory", "")
	if err != nil {
		log.Fatal(err)
	}
	oauthServer, err := oauth.NewSupabaseMCPOAuthServer(*serverURL, *mcpResource, *supabaseURL, *supabaseKey, keymanager)
	if err != nil {
		log.Fatal(err)
	}
	oauthServer.RegisterHTTP(mux)

	// Register your tools endpoints.
	tools.RegisterHTTP(mux, *serverURL)

	// Register the default handler for unhandled paths.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Handling request for unhandled path: %s", r.URL.Path)
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// OPTIONAL: Create a CORS checker and register the MCP server.
	// This is useful if you want to allow requests from other domains and you're
	// using something like the [MCP Inspector](https://modelcontextprotocol.io/legacy/tools/inspector)
	// this comes in super handy.
	originAllowlist := []string{
		"http://localhost:3000",
		"http://localhost:3001",
		"http://localhost:4000",
		"http://localhost:4001",
		"http://localhost:6274",
	}
	corsChecker := mcp.NewAllowlistCorsChecker(originAllowlist)

	log.Fatal(http.ListenAndServe(hostPort, mcp.CheckCORS(mux, corsChecker)))
}
```

5. Run your server:
```bash
go run main.go
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SUPABASE_URL` | Your Supabase project URL | Yes |
| `SUPABASE_KEY` | Your Supabase anon key | Yes |
| `BASE_URL` | External base URL of this server | Yes |
| `MCP_RESOURCE` | MCP resource identifier | Yes |

### OAuth Provider Setup

Configure OAuth providers in your Supabase project:

1. **Google OAuth**: Add your Google OAuth credentials in Supabase Auth settings
2. **Microsoft OAuth**: Configure Azure AD application in Supabase Auth settings

## API Endpoints

### Authorization Endpoints

- `GET /authorize` - OAuth authorization endpoint (serves login page)
- `POST /authorize` - Process authorization requests
- `GET /callback` - OAuth callback handler
- `POST /token` - Token exchange endpoint

### Client Registration (RFC 7591)

- `POST /register` - Register new OAuth client
- `GET /register/{client_id}` - Retrieve client information (requires registration token)

### Discovery Endpoints

- `GET /.well-known/oauth-authorization-server` - OAuth server metadata
- `GET /.well-known/oauth-protected-resource` - Protected resource metadata
- `GET /.well-known/openid-configuration` - OpenID Connect discovery

## Usage Examples

### Registering a New Client

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["http://localhost:3000/callback"],
    "client_name": "My MCP Client",
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

### Initiating OAuth Flow

```bash
# Redirect user to:
http://localhost:8080/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_CALLBACK&response_type=code&state=random_state&code_challenge=YOUR_CHALLENGE&code_challenge_method=S256
```

### Exchanging Authorization Code

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'grant_type=authorization_code&code=AUTH_CODE&redirect_uri=YOUR_CALLBACK&client_id=YOUR_CLIENT_ID&client_secret=YOUR_SECRET&code_verifier=YOUR_VERIFIER'
```

## Security Features

- **PKCE Support**: Protects against authorization code interception
- **Secure Token Generation**: Cryptographically secure random token generation
- **CORS Configuration**: Configurable origin allowlists
- **Bearer Token Authentication**: Standard OAuth 2.0 bearer token support
- **Client Secret Protection**: Optional client secrets for confidential clients

## Development

### Project Structure

```
* mcp/
   * cors.go          # CORS middleware and configuration
* oauth/
   * oauth.go         # Main OAuth server implementation
   * registry.go      # Dynamic client registration (RFC 7591)
   * rfc7591.go       # Client registration data structures
   * login.html       # OAuth login page
   * wellknown/       # Discovery endpoints
       * wellknown.go # Well-known endpoint handlers
       * oidc.go      # OpenID Connect discovery
       * rfc8414.go   # OAuth server metadata
       * rfc9728.go   # OAuth protected resource metadata
* go.mod
* go.sum
```

### Building

```bash
go build -o oauth-server
./oauth-server
```

### Testing

Set up test environment variables and run:
```bash
go test ./...
```

## Standards Compliance

This implementation follows these RFCs and specifications:

- **RFC 6749**: OAuth 2.0 Authorization Framework
- **RFC 7591**: OAuth 2.0 Dynamic Client Registration Protocol  
- **RFC 7636**: Proof Key for Code Exchange (PKCE)
- **RFC 8414**: OAuth 2.0 Authorization Server Metadata
- **RFC 9728**: OAuth 2.0 Protected Resource Metadata
- **OpenID Connect Discovery**: OpenID Connect metadata endpoint

## License

See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request