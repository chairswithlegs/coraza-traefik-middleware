package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdminHandler(t *testing.T) {
	// Create test handler for admin endpoints
	adminHandler := NewAdminHandler()
	if adminHandler == nil {
		t.Fatal("Expected admin handler to be non-nil")
	}
	adminServer := httptest.NewServer(adminHandler)
	defer adminServer.Close()

	t.Run("Health check should respond with 200 OK", func(t *testing.T) {
		req, err := http.NewRequest("GET", adminServer.URL+"/health", nil)
		assert.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected status code 200 OK")
	})

	t.Run("Metrics endpoint should respond with 200 OK", func(t *testing.T) {
		req, err := http.NewRequest("GET", adminServer.URL+"/metrics", nil)
		assert.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected status code 200 OK")
	})
}
