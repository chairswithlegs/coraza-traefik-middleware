package admin

import (
	"log/slog"
	"net/http"

	"github.com/chairswithlegs/coraza-traefik-middleware/src/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewAdminHandler creates a separate HTTP server for administrative endpoints
func NewAdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.Handle("/metrics", promhttp.Handler())
	// Add Datadog tracing and logging to admin endpoints
	handler := middleware.LoggingMiddleware(mux, slog.LevelDebug)
	handler = middleware.PanicMiddleware(handler)
	return handler
}

// healthHandler provides a basic health check endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","service":"coraza-waf-server"}`))
}
