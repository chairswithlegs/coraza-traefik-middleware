package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProxyHeaderMiddleware(t *testing.T) {
	// Create a test handler that captures the modified request
	var capturedRequest *http.Request
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRequest = r
		w.WriteHeader(http.StatusOK)
	})

	// Wrap the test handler with the proxy header middleware
	middleware := ProxyHeaderMiddleware(testHandler)

	t.Run("Should process X-Forwarded-For header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"             // Original proxy IP
		req.Header.Set("X-Forwarded-For", "203.0.113.195") // Real client IP

		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		assert.Equal(t, "203.0.113.195:12345", capturedRequest.RemoteAddr, "Should update RemoteAddr with client IP but keep original port")
	})

	t.Run("Should process X-Forwarded-For with multiple IPs", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.100:8080"
		req.Header.Set("X-Forwarded-For", "203.0.113.195, 198.51.100.178, 192.168.1.100") // Client, proxy1, proxy2

		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		assert.Equal(t, "203.0.113.195:8080", capturedRequest.RemoteAddr, "Should use leftmost IP as client IP")
	})

	t.Run("Should handle X-Forwarded-For with spaces", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.100:443"
		req.Header.Set("X-Forwarded-For", "  203.0.113.195  ,  198.51.100.178  ") // IPs with spaces

		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		assert.Equal(t, "203.0.113.195:443", capturedRequest.RemoteAddr, "Should trim spaces from IP addresses")
	})

	t.Run("Should handle RemoteAddr without port", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.100" // No port
		req.Header.Set("X-Forwarded-For", "203.0.113.195")

		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		assert.Equal(t, "203.0.113.195:0", capturedRequest.RemoteAddr, "Should default to port 0 when original has no port")
	})

	t.Run("Should process X-Forwarded-Proto header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Forwarded-Proto", "https")

		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		assert.Equal(t, "https", capturedRequest.URL.Scheme, "Should update URL scheme from X-Forwarded-Proto")
	})

	t.Run("Should process X-Forwarded-Host header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Forwarded-Host", "example.com")

		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		assert.Equal(t, "example.com", capturedRequest.Host, "Should update Host from X-Forwarded-Host")
		assert.Equal(t, "example.com", capturedRequest.URL.Host, "Should update URL.Host from X-Forwarded-Host")
	})

	t.Run("Should process all headers together", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.100:8080"
		req.Header.Set("X-Forwarded-For", "203.0.113.195")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		assert.Equal(t, "203.0.113.195:8080", capturedRequest.RemoteAddr, "Should process X-Forwarded-For")
		assert.Equal(t, "https", capturedRequest.URL.Scheme, "Should process X-Forwarded-Proto")
		assert.Equal(t, "api.example.com", capturedRequest.Host, "Should process X-Forwarded-Host")
		assert.Equal(t, "api.example.com", capturedRequest.URL.Host, "Should process X-Forwarded-Host for URL")
	})

	t.Run("Should pass through request without headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		originalRemoteAddr := "192.168.1.100:8080"
		originalHost := "localhost"
		req.RemoteAddr = originalRemoteAddr
		req.Host = originalHost

		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		assert.Equal(t, originalRemoteAddr, capturedRequest.RemoteAddr, "Should preserve original RemoteAddr")
		assert.Equal(t, originalHost, capturedRequest.Host, "Should preserve original Host")
		assert.Equal(t, "", capturedRequest.URL.Scheme, "Should preserve empty scheme")
	})

	t.Run("Should handle empty header values", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		originalRemoteAddr := "192.168.1.100:8080"
		req.RemoteAddr = originalRemoteAddr
		req.Header.Set("X-Forwarded-For", "") // Empty value
		req.Header.Set("X-Forwarded-Proto", "")
		req.Header.Set("X-Forwarded-Host", "")
		req.Header.Set("X-Forwarded-Uri", "")
		req.Header.Set("X-Forwarded-Method", "")

		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		assert.Equal(t, originalRemoteAddr, capturedRequest.RemoteAddr, "Should preserve original RemoteAddr when X-Forwarded-For is empty")
	})

	t.Run("Should handle malformed X-Forwarded-For", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		originalRemoteAddr := "192.168.1.100:8080"
		req.RemoteAddr = originalRemoteAddr
		req.Header.Set("X-Forwarded-For", ",,,") // Only commas

		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		assert.Equal(t, originalRemoteAddr, capturedRequest.RemoteAddr, "Should preserve original RemoteAddr when X-Forwarded-For is malformed")
	})

	t.Run("Should handle path header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/original-path", nil)
		req.Header.Set("X-Forwarded-Uri", "/new-path")

		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		assert.Equal(t, "/new-path", capturedRequest.URL.Path, "Should update URL path from X-Forwarded-Uri")
	})

	t.Run("Should handle method header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Forwarded-Method", "POST")

		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		assert.Equal(t, "POST", capturedRequest.Method, "Should update method from X-Forwarded-Method")
	})
}
