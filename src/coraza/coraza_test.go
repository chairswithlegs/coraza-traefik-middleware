package coraza

import (
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/chairswithlegs/coraza-traefik-middleware/src/audit"
	"github.com/stretchr/testify/assert"
)

const mockDirectives = `
SecDebugLog /dev/stdout
SecDebugLogLevel 3
Include @coraza.conf-recommended
SecDefaultAction phase:1,log,auditlog,pass
SecDefaultAction phase:2,log,auditlog,pass
SecAction id:900990,phase:1,pass,t:none,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.17.1',setvar:tx.crs_setup_version=4171
Include @owasp_crs/*.conf
SecRuleEngine On`

func TestCorazaWAFHandler(t *testing.T) {
	tempDir := t.TempDir()
	auditLogProcessor := audit.NewLogProcessor(audit.AuditLogProcessorOptions{
		AuditLogPath: path.Join(tempDir, "audit.log"),
	})

	t.Setenv("DIRECTIVES", mockDirectives)

	// Create test handler for WAF
	wafHandler := NewCorazaWAFHandler(auditLogProcessor)
	if wafHandler == nil {
		t.Fatal("Expected WAF handler to be non-nil")
	}
	wafServer := httptest.NewServer(wafHandler)
	defer wafServer.Close()

	t.Run("Should respond with 200 OK", func(t *testing.T) {
		req, err := http.NewRequest("GET", wafServer.URL, nil)
		assert.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected status code 200 OK")
	})

	t.Run("Should reject a sketchy request", func(t *testing.T) {
		requestURL := wafServer.URL + "?file=../../etc/passwd"
		req, err := http.NewRequest("GET", requestURL, nil)
		assert.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "Expected status code 403 Forbidden")
	})
}

func TestLoadDirectivesFromEnv(t *testing.T) {
	// Set an environment variable for testing
	t.Setenv("DIRECTIVES", "SecDebugLog /dev/stdout\nSecDebugLogLevel 9")

	directives, err := loadDirectivesFromEnv()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	expected := "SecDebugLog /dev/stdout\nSecDebugLogLevel 9"
	if directives != expected {
		t.Errorf("Expected directives to be %q, got %q", expected, directives)
	}
}

func TestProxyHeaderIntegrationWithWAF(t *testing.T) {
	tempDir := t.TempDir()
	auditLogProcessor := audit.NewLogProcessor(audit.AuditLogProcessorOptions{
		AuditLogPath: path.Join(tempDir, "audit.log"),
	})

	t.Setenv("DIRECTIVES", mockDirectives)

	// Create WAF handler with proxy header middleware
	wafHandler := NewCorazaWAFHandler(auditLogProcessor)
	server := httptest.NewServer(wafHandler)
	defer server.Close()

	t.Run("WAF should see real client IP from X-Forwarded-For", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/", nil)
		assert.NoError(t, err)

		// Simulate Traefik forwarding a request
		req.Header.Set("X-Forwarded-For", "203.0.113.195") // Real client IP
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "Request should pass through WAF")
	})

	t.Run("WAF should block attack from real client IP", func(t *testing.T) {
		// Test that the WAF processes the real client IP for security decisions
		req, err := http.NewRequest("GET", server.URL+"/?file=../../etc/passwd", nil)
		assert.NoError(t, err)

		// Simulate Traefik forwarding a malicious request
		req.Header.Set("X-Forwarded-For", "203.0.113.195") // Real client IP (attacker)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "WAF should block malicious request from real client IP")
	})
}
