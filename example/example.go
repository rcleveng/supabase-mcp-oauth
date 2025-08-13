package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	somcp "github.com/rcleveng/supabase-mcp-oauth/mcp"
	"github.com/rcleveng/supabase-mcp-oauth/oauth"
	"github.com/rcleveng/supabase-mcp-oauth/oauth/wrappedjwt"

	"github.com/joho/godotenv"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	host        = flag.String("host", "localhost", "host to listen on")
	port        = flag.String("port", "8080", "port to listen on")
	serverURL   = flag.String("server-url", "", "server url to listen on")
	mcpResource = flag.String("mcp-resource", "", "mcp resource to listen on")
	supabaseURL = flag.String("supabase-url", os.Getenv("SUPABASE_URL"), "supabase url to listen on")
	supabaseKey = flag.String("supabase-key", os.Getenv("SUPABASE_KEY"), "supabase key to listen on")
)

func middleware(next http.Handler, baseURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Middleware:Handling request for URL '%s'\n", r.URL.Path)
		authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
		resourceMetadata := baseURL + "/.well-known/oauth-protected-resource"
		if len(authHeader) != 2 {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="mcp-server", resource_metadata="%s"`, resourceMetadata))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		token := authHeader[1]
		if token != "CHANGEME-access_token" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="mcp-server", resource_metadata="%s"`, resourceMetadata))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type HealthParams struct {
	Name string `json:"name"`
}

func HandleHealth(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[HealthParams]) (*mcp.CallToolResultFor[any], error) {
	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "ok " + params.Arguments.Name},
		},
	}, nil
}

func RegisterHTTP(mux *http.ServeMux, serverURL string) {

	server := mcp.NewServer(&mcp.Implementation{Name: "sse"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "health", Description: "check health"}, HandleHealth)

	server.AddReceivingMiddleware(func(next mcp.MethodHandler[*mcp.ServerSession]) mcp.MethodHandler[*mcp.ServerSession] {
		return func(ctx context.Context, cc *mcp.ServerSession, method string, params mcp.Params) (mcp.Result, error) {
			log.Printf("Received method=%s params=%T", method, params)
			return next(ctx, cc, method, params)
		}
	})

	streamableHandler := mcp.NewStreamableHTTPHandler(func(request *http.Request) *mcp.Server {
		log.Printf("NewStreamableHTTPHandler:Handling request for URL '%s'\n", request.URL.Path)
		return server
	}, nil)

	mux.HandleFunc("/sse", middleware(streamableHandler, serverURL).ServeHTTP)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	if *supabaseURL == "" {
		*supabaseURL = os.Getenv("SUPABASE_URL")
	}
	if *supabaseKey == "" {
		*supabaseKey = os.Getenv("SUPABASE_KEY")
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
	// Create some default keys.
	keyManager.FindOrCreateForPurpose(wrappedjwt.KeyPurposeSigning)
	keyManager.FindOrCreateForPurpose(wrappedjwt.KeyPurposeEncryption)

	oauthServer, err := oauth.NewSupabaseMCPOAuthServer(*serverURL, *mcpResource, *supabaseURL, *supabaseKey, keyManager)
	if err != nil {
		log.Fatal(err)
	}
	oauthServer.RegisterHTTP(mux)

	// Register your tools endpoints.
	RegisterHTTP(mux, *serverURL)

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
	corsChecker := somcp.NewAllowlistCorsChecker(originAllowlist)

	slog.Info("Starting server", "host:port", hostPort)
	log.Fatal(http.ListenAndServe(hostPort, somcp.CheckCORS(mux, corsChecker)))
}
