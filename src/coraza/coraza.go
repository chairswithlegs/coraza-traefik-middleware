package coraza

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/chairswithlegs/coraza-traefik-middleware/src/audit"
	"github.com/chairswithlegs/coraza-traefik-middleware/src/middleware"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
)

func NewCorazaWAFHandler(auditLogProcessor *audit.LogProcessor) http.Handler {
	// Create the WAF configuration
	cfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS) // Use the embedded Core Rule Set

	directivesFromEnv, err := loadDirectivesFromEnv()
	if err != nil {
		slog.Error("Failed to load WAF directives", "error", err)
		log.Fatal(err)
	}
	if len(directivesFromEnv) > 0 {
		cfg = cfg.WithDirectives(directivesFromEnv)
	}

	slog.Info("Setting audit log directives to support log processing")
	cfg = auditLogProcessor.SetAuditLogDirectives(cfg)

	// Create the WAF instance
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		slog.Error("Failed to create WAF instance", "error", err)
		log.Fatal(err)
	}

	slog.Info("WAF client initialized successfully")

	mux := http.NewServeMux()
	// Configure the WAF HTTP handler with proxy header middleware
	handler := wafHandler(waf, auditLogProcessor)
	handler = middleware.ProxyHeaderMiddleware(handler)
	handler = middleware.LoggingMiddleware(handler, slog.LevelDebug)
	handler = middleware.PanicMiddleware(handler)
	mux.Handle("/", handler)
	return mux
}

func wafHandler(waf coraza.WAF, auditLogProcessor *audit.LogProcessor) http.Handler {
	handler := txhttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure the audit log hasn't been locked by the log processor
		auditLogProcessor.Lock.Lock()
		defer auditLogProcessor.Lock.Unlock()

		handler.ServeHTTP(w, r)
	})
}

func loadDirectivesFromEnv() (string, error) {
	directives := os.Getenv("DIRECTIVES")

	if directives == "" {
		return "", fmt.Errorf("DIRECTIVES environment variable is required but not set")
	}

	// Basic validation - check for required directives
	requiredDirectives := []string{"SecRuleEngine"}
	for _, required := range requiredDirectives {
		if !strings.Contains(directives, required) {
			slog.Warn("Missing recommended directive", "directive", required)
		}
	}

	slog.Info("Loaded WAF directives from environment", "length", len(directives))
	return directives, nil
}
