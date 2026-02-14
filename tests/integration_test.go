//go:build integration

package tests

import (
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	baseURLTraefik = "http://localhost:8000"
	baseURLAdmin   = "http://localhost:8081"
	readinessWait  = 2 * time.Second
	readinessTries = 5
)

func TestMain(m *testing.M) {
	if err := waitForStack(); err != nil {
		os.Stderr.WriteString("integration: stack not ready: " + err.Error() + "\nRun 'make run' first.\n")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// waitForStack retries GET baseURLAdmin/health until 200 or max attempts.
func waitForStack() error {
	client := &http.Client{Timeout: 5 * time.Second}
	url := baseURLAdmin + "/health"
	for i := 0; i < readinessTries; i++ {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if i < readinessTries-1 {
			time.Sleep(readinessWait)
		}
	}
	return errors.New("admin health did not return 200 after retries")
}

func TestAdminHealth(t *testing.T) {
	resp, err := http.Get(baseURLAdmin + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// body contains "status":"healthy"
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])
	assert.Contains(t, bodyStr, `"status":"healthy"`, "health response should contain status healthy")
}

func TestFullStackAllowed(t *testing.T) {
	resp, err := http.Get(baseURLTraefik + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "clean request through Traefik -> WAF -> whoami should return 200")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Greater(t, len(body), 0, "whoami should return a body")
}

func TestRequestBlockedByWAF(t *testing.T) {
	req, err := http.NewRequest("GET", baseURLTraefik+"/?file=../../etc/passwd", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "path traversal via query should be blocked by WAF (403)")
}

func TestBypassRoute(t *testing.T) {
	req, err := http.NewRequest("GET", baseURLTraefik+"/?file=../../etc/passwd", nil)
	require.NoError(t, err)
	req.Header.Set("X-WAF-Disabled", "true")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "request with X-WAF-Disabled should skip WAF and reach whoami")
}
