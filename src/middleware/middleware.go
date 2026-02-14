package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// PanicMiddleware recovers from panics in HTTP handlers
func PanicMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("Recovered from panic in HTTP handler", "error", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ProxyHeaderMiddleware processes X-Forwarded-* headers from Traefik
func ProxyHeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
			// Take the first one (leftmost) as the original client IP
			if ips := strings.Split(xff, ","); len(ips) > 0 {
				clientIP := strings.TrimSpace(ips[0])
				if clientIP != "" {
					// Update the request's RemoteAddr to reflect the real client IP
					// Keep the port from the original RemoteAddr if possible
					if _, port, err := net.SplitHostPort(r.RemoteAddr); err == nil {
						r.RemoteAddr = net.JoinHostPort(clientIP, port)
					} else {
						r.RemoteAddr = clientIP + ":0"
					}
				}
			}
		}

		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			r.URL.Scheme = proto
		}

		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			r.Host = host
			r.URL.Host = host
		}

		if uri := r.Header.Get("X-Forwarded-Uri"); uri != "" {
			r.URL.Path = uri
		}

		if method := r.Header.Get("X-Forwarded-Method"); method != "" {
			r.Method = method
		}

		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs incoming requests
func LoggingMiddleware(next http.Handler, logLevel slog.Level) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)
		duration := time.Since(start)
		slog.Log(r.Context(), logLevel, "HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
			"status", lrw.statusCode,
			"duration_ms", duration.Milliseconds(),
		)
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}
