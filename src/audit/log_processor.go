package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"
)

// LogProcessor is a background service that will continuously monitor and process Coraza audit logs
// This includes:
// - Expiring audit logs that are older than a certain age
// - Processing audit logs and sending metrics to Prometheus
type LogProcessor struct {
	auditLogDir  string
	auditLogFile string
	logger       *slog.Logger
	logHandler   func(log Log) error

	processingDone chan struct{}
	expirationDone chan struct{}
	stopSignal     chan struct{}

	ProcessingJobInterval time.Duration
	ExpirationJobInterval time.Duration
	LogExpiration         time.Duration
	Lock                  *sync.Mutex
}

type AuditLogProcessorOptions struct {
	AuditLogPath          string
	ProcessingJobInterval time.Duration
	ExpirationJobInterval time.Duration
	LogExpiration         time.Duration
}

func NewLogProcessor(options AuditLogProcessorOptions) *LogProcessor {
	processor := &LogProcessor{
		auditLogDir:  path.Dir(options.AuditLogPath),
		auditLogFile: path.Base(options.AuditLogPath),
		logger:       slog.Default(),

		stopSignal: make(chan struct{}),

		ProcessingJobInterval: options.ProcessingJobInterval,
		ExpirationJobInterval: options.ExpirationJobInterval,
		LogExpiration:         options.LogExpiration,
		Lock:                  &sync.Mutex{},
	}

	processor.logHandler = processor.defaultLogHandler
	return processor
}

// SetAuditLogDirectives configures the WAF to use the audit log settings required for processing
func (p *LogProcessor) SetAuditLogDirectives(cfg coraza.WAFConfig) coraza.WAFConfig {
	auditLogDirectives := fmt.Sprintf(`
	  SecAuditLog %s
		SecAuditLogParts AFHKZ
		SecAuditLogFormat JSON
		SecAuditLogType Serial
		SecAuditEngine On`, path.Join(p.auditLogDir, p.auditLogFile))

	return cfg.WithDirectives(auditLogDirectives)
}

// StartProcessingJob begins the log processing loop
func (p *LogProcessor) StartProcessingJob() {
	p.logger.Info("Starting audit log processing job", "interval", p.ProcessingJobInterval.String())

	ticker := time.NewTicker(p.ProcessingJobInterval)
	defer ticker.Stop()

	p.processingDone = make(chan struct{})
	defer close(p.processingDone) // Signal that processing has stopped

	for {
		select {
		case <-p.stopSignal:
			return
		case <-ticker.C:
			exist, err := p.checkIfLogsExist()
			if err != nil {
				p.logger.Error("Failed to check for audit logs", "error", err)
				continue
			}

			if !exist {
				continue
			}

			filename, err := p.rotateLogs()
			if err != nil {
				p.logger.Error("Failed to rotate audit log", "error", err)
				continue
			}

			if err = p.ProcessLogFile(filename); err != nil {
				p.logger.Error("Failed to process audit log file", "error", err, "file", filename)
				continue
			}
		}
	}
}

// StartExpirationJob begins the log expiration loop
func (p *LogProcessor) StartExpirationJob() {
	p.logger.Info("Starting audit log expiration job", "interval", p.ExpirationJobInterval.String(), "expiration", p.LogExpiration.String())

	ticker := time.NewTicker(p.ExpirationJobInterval)
	defer ticker.Stop()

	p.expirationDone = make(chan struct{})
	defer close(p.expirationDone) // Signal that expiration has stopped

	for {
		select {
		case <-p.stopSignal:
			return
		case <-ticker.C:
			if err := p.expireBackupLogFiles(); err != nil {
				p.logger.Error("Failed to expire backup log files", "error", err)
			}
		}
	}
}

// Stop gracefully stops the processor and waits for completion
func (p *LogProcessor) Stop(ctx context.Context) error {
	p.logger.Info("Stopping audit log processor...")
	close(p.stopSignal) // Signal the processing loop to stop

	// Wait for any async jobss to finish
	jobsDone := make(chan struct{})
	go func() {
		if p.processingDone != nil {
			<-p.processingDone
		}
		if p.expirationDone != nil {
			<-p.expirationDone
		}
		close(jobsDone)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-jobsDone:
		p.logger.Info("Audit log processor stopped gracefully")
		return nil
	}
}

// ProcessLogFile processes each entry in the given audit log file. Individual entries that fail to
// parse or process are skipped and summarized in a single warning (or an error, if every entry
// failed); an error is only returned if the file itself cannot be read.
func (p *LogProcessor) ProcessLogFile(filename string) error {
	p.logger.Debug("Processing audit log file", "file", filename)
	start := time.Now()

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var entries, violations, parseErrors, handlerErrors int
	var firstErr error

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		entries++
		var logEntry Log

		if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
			p.logger.Debug("Failed to parse audit log entry, skipping", "error", err, "line", line)
			parseErrors++
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to parse log entry: %w", err)
			}
			continue
		}

		if err := p.logHandler(logEntry); err != nil {
			p.logger.Debug("Failed to handle audit log entry", "error", err, "id", logEntry.Transaction.ID)
			handlerErrors++
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to handle log entry %s: %w", logEntry.Transaction.ID, err)
			}
			continue
		}

		if len(logEntry.Messages) > 0 {
			violations++
		}
	}

	if err = scanner.Err(); err != nil {
		return fmt.Errorf("failed to read log file after %d entries: %w", entries, err)
	}

	summary := []any{
		"file", filename,
		"entries", entries,
		"violations", violations,
		"parse_errors", parseErrors,
		"handler_errors", handlerErrors,
		"duration", time.Since(start).String(),
	}
	if failures := parseErrors + handlerErrors; failures > 0 && failures == entries {
		p.logger.Error("All entries failed while processing audit log file", append(summary, "first_error", firstErr)...)
	} else if firstErr != nil {
		p.logger.Warn("Errors occurred while processing audit log file", append(summary, "first_error", firstErr)...)
	} else {
		p.logger.Debug("Completed processing audit log file", summary...)
	}

	return nil
}

func (p *LogProcessor) rotateLogs() (filename string, err error) {
	logPath := path.Join(p.auditLogDir, p.auditLogFile)

	p.Lock.Lock()
	defer p.Lock.Unlock()

	// Open for reading to copy content
	auditLog, err := os.Open(logPath)
	if err != nil {
		return "", fmt.Errorf("failed to open audit log: %w", err)
	}
	defer auditLog.Close()

	copyName := p.generateNewBackupFilename(time.Now())
	copyFile, err := os.Create(copyName)
	if err != nil {
		return "", fmt.Errorf("failed to create copy of audit log: %w", err)
	}
	defer copyFile.Close()

	if _, err := io.Copy(copyFile, auditLog); err != nil {
		return "", fmt.Errorf("failed to copy audit log contents: %w", err)
	}

	auditLog.Close()

	if err := os.Truncate(logPath, 0); err != nil {
		return "", fmt.Errorf("failed to truncate audit log: %w", err)
	}

	return copyName, nil
}

func (p *LogProcessor) expireBackupLogFiles() error {
	p.logger.Debug("Checking for expired audit log files to delete", "expiration", p.LogExpiration.String())

	files, err := os.ReadDir(p.auditLogDir)
	if err != nil {
		return fmt.Errorf("failed to read audit log directory: %w", err)
	}

	now := time.Now()
	deleted := 0
	for _, file := range files {
		if file.IsDir() || !file.Type().IsRegular() {
			continue
		}

		if !p.isBackupFile(file.Name()) {
			continue
		}

		timestamp, err := p.parseTimestampFromBackupFilename(file.Name())
		if err != nil {
			p.logger.Warn("Failed to parse timestamp from backup log filename, skipping", "file", file.Name(), "error", err)
			continue
		}

		if now.Sub(timestamp) > p.LogExpiration {
			fullPath := path.Join(p.auditLogDir, file.Name())
			if err := os.Remove(fullPath); err != nil {
				p.logger.Warn("Failed to delete expired audit log file", "file", fullPath, "error", err)
			} else {
				p.logger.Debug("Deleted expired audit log file", "file", fullPath)
				deleted++
			}
		}
	}

	if deleted > 0 {
		p.logger.Info("Deleted expired audit log files", "count", deleted, "expiration", p.LogExpiration.String())
	}

	return nil
}

func (p *LogProcessor) checkIfLogsExist() (bool, error) {
	logPath := path.Join(p.auditLogDir, p.auditLogFile)
	info, err := os.Stat(logPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to stat audit log: %w", err)
	}

	if info.Size() == 0 {
		return false, nil
	}
	return true, nil
}

// ruleMatch is the structured representation of a matched rule in the "Rule violations" log
type ruleMatch struct {
	RuleID  string `json:"rule_id"`
	Message string `json:"message"`
}

func (p *LogProcessor) defaultLogHandler(log Log) error {
	p.logger.Debug("Processing log entry", "id", log.Transaction.ID, "messages", len(log.Messages))

	if len(log.Messages) == 0 {
		return nil
	}

	logFields := []any{
		"id", log.Transaction.ID,
		"client_ip", log.Transaction.ClientIP,
	}

	request := log.Transaction.Request
	if request != nil {
		logFields = append(logFields,
			"method", request.Method,
			"uri", request.URI,
			"protocol", request.Protocol,
		)
	}

	rules := make([]ruleMatch, 0, len(log.Messages))
	for _, msg := range log.Messages {
		rules = append(rules, ruleMatch{
			RuleID:  fmt.Sprintf("%s-%d", msg.Data.File, msg.Data.ID),
			Message: msg.Data.Msg,
		})
	}
	logFields = append(logFields, "rules", rules)
	p.logger.Warn("Rule violations", logFields...)

	sendTransactionMetrics(log)
	sendRuleViolationMetrics(log)
	return nil
}

func (p *LogProcessor) generateNewBackupFilename(timestamp time.Time) string {
	timestampStr := strconv.FormatInt(timestamp.Unix(), 10)
	return path.Join(p.auditLogDir, fmt.Sprintf("%s.%s", p.auditLogFile, timestampStr))
}

func (p *LogProcessor) parseTimestampFromBackupFilename(filename string) (time.Time, error) {
	base := path.Base(filename)
	timestampStr := strings.TrimPrefix(base, p.auditLogFile+".")
	timestampInt, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp in filename: %w", err)
	}

	return time.Unix(timestampInt, 0), nil
}

func (p *LogProcessor) isBackupFile(filename string) bool {
	base := path.Base(filename)
	if !strings.HasPrefix(base, p.auditLogFile+".") {
		return false
	}

	_, err := p.parseTimestampFromBackupFilename(filename)
	return err == nil
}
