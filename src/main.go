package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chairswithlegs/coraza-traefik-middleware/src/admin"
	"github.com/chairswithlegs/coraza-traefik-middleware/src/audit"
	"github.com/chairswithlegs/coraza-traefik-middleware/src/coraza"
)

var (
	expirationStr            = getEnvOrDefault("AUDIT_LOG_EXPIRATION", "24h")
	expirationJobIntervalStr = getEnvOrDefault("AUDIT_LOG_EXPIRATION_JOB_INTERVAL", "1h")
	processingJobIntervalStr = getEnvOrDefault("AUDIT_LOG_PROCESSING_JOB_INTERVAL", "10s")
	auditLogPath             = getEnvOrDefault("AUDIT_LOG_PATH", "/var/log/coraza-audit.log")
	logLevel                 = getEnvOrDefault("LOG_LEVEL", "info")
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: getLogLevel(),
	}))
	slog.SetDefault(logger)

	// Process audit logs in the background
	processor := audit.NewLogProcessor(auditLogProcessorOptions())
	go processor.StartProcessingJob()
	go processor.StartExpirationJob()

	// Start the servers
	wafHandler := coraza.NewCorazaWAFHandler(processor)
	adminHandler := admin.NewAdminHandler()
	wafServer, adminServer := runServersInBackground(wafHandler, adminHandler)

	// Handle graceful shutdown
	handleShutdown(wafServer, adminServer, processor)
}

func getEnvOrDefault(envVar string, defaultValue string) string {
	if value := os.Getenv(envVar); value != "" {
		return value
	}
	return defaultValue
}

func runServersInBackground(wafHandler http.Handler, adminHandler http.Handler) (wafServer *http.Server, adminServer *http.Server) {
	wafPort := ":8080"
	if envWafPort := os.Getenv("WAF_PORT"); envWafPort != "" {
		wafPort = ":" + envWafPort
	}

	adminPort := ":8081"
	if envAdminPort := os.Getenv("ADMIN_PORT"); envAdminPort != "" {
		adminPort = ":" + envAdminPort
	}

	// Start the servers

	wafServer = &http.Server{
		Addr:              wafPort,
		Handler:           wafHandler,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	adminServer = &http.Server{
		Addr:              adminPort,
		Handler:           adminHandler,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		slog.Info("Starting WAF server", "port", wafPort)
		if err := wafServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("WAF server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	go func() {
		slog.Info("Starting admin server", "port", adminPort)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Admin server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	return wafServer, adminServer
}

func handleShutdown(wafServer *http.Server, adminServer *http.Server, processor *audit.LogProcessor) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("Shutting down background services...")

	// Wait up to 30 seconds for in-flight requests to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	wafShutdownErr := wafServer.Shutdown(ctx)
	adminShutdownErr := adminServer.Shutdown(ctx)
	processorErr := processor.Stop(ctx)

	if wafShutdownErr != nil {
		slog.Error("WAF server forced to shutdown", "error", wafShutdownErr)
	}
	if adminShutdownErr != nil {
		slog.Error("Admin server forced to shutdown", "error", adminShutdownErr)
	}
	if processorErr != nil {
		slog.Error("Log processor forced to shutdown", "error", processorErr)
	}

	if wafShutdownErr != nil || adminShutdownErr != nil || processorErr != nil {
		os.Exit(1)
	}

	slog.Info("Applications exited gracefully")
}

func getLogLevel() slog.Level {
	switch logLevel {
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "debug":
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

func auditLogProcessorOptions() audit.AuditLogProcessorOptions {
	opts := audit.AuditLogProcessorOptions{
		AuditLogPath: auditLogPath,
	}

	if expirationStr != "" {
		logExpiration, err := time.ParseDuration(expirationStr)
		if err != nil {
			slog.Error("Failed to parse log expiration duration", "error", err)
			os.Exit(1)
		}
		opts.LogExpiration = logExpiration
	}

	if expirationJobIntervalStr != "" {
		expirationJobInterval, err := time.ParseDuration(expirationJobIntervalStr)
		if err != nil {
			slog.Error("Failed to parse log expiration job interval", "error", err)
			os.Exit(1)
		}
		opts.ExpirationJobInterval = expirationJobInterval
	}

	if processingJobIntervalStr != "" {
		processingJobInterval, err := time.ParseDuration(processingJobIntervalStr)
		if err != nil {
			slog.Error("Failed to parse log processing job interval", "error", err)
			os.Exit(1)
		}
		opts.ProcessingJobInterval = processingJobInterval
	}

	return opts
}
