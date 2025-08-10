package mcp

import (
	"log/slog"
	"net/http"
	"slices"
	"strings"
)

var method_allowlist = []string{"GET", "POST", "DELETE", "OPTIONS"}

func NewAllowlistCorsChecker(originAllowlist []string) CorsChecker {
	return &allowlistCorsChecker{
		originAllowlist: originAllowlist,
		methodAllowlist: method_allowlist,
	}
}

func NewAllowAllCorsChecker() CorsChecker {
	return &allowAllCorsChecker{}
}

type allowAllCorsChecker struct{}

func (*allowAllCorsChecker) Check(*http.Request) bool {
	return true
}

type CorsChecker interface {
	Check(r *http.Request) bool
}

type allowlistCorsChecker struct {
	originAllowlist []string
	methodAllowlist []string
}

func isPreflight(r *http.Request) bool {
	return r.Method == "OPTIONS" &&
		r.Header.Get("Origin") != "" &&
		r.Header.Get("Access-Control-Request-Method") != ""
}

func (a *allowlistCorsChecker) Check(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	preflight := isPreflight(r)
	if !preflight {
		return slices.Contains(a.originAllowlist, origin)
	}
	method := r.Header.Get("Access-Control-Request-Method")
	return slices.Contains(a.originAllowlist, origin) && slices.Contains(a.methodAllowlist, method)
}

func CheckCORS(next http.Handler, checker CorsChecker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		method := r.Header.Get("Access-Control-Request-Method")
		if isPreflight(r) {
			slog.Debug("Preflight request", "origin", origin, "method", method)
			if checker.Check(r) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(method_allowlist, ", "))
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version")
			} else if origin != "" {
				slog.Warn("Preflight request: Origin not allowed", "origin", origin)
			}
		} else {
			// Not a preflight: regular request.
			if checker.Check(r) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else if origin != "" {
				slog.Warn("Regular request: Origin not allowed", "origin", origin)
			}
		}
		w.Header().Add("Vary", "Origin")
		next.ServeHTTP(w, r)
	})
}
