package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLogProcessor(t *testing.T) {
	tempDir := t.TempDir()
	logFile := path.Join(tempDir, "audit.log")

	logs := make([]Log, 0)
	handler := func(l Log) error {
		logs = append(logs, l)
		return nil
	}

	processor := NewLogProcessor(AuditLogProcessorOptions{
		AuditLogPath:          logFile,
		ProcessingJobInterval: time.Second,
	})
	processor.logHandler = handler

	// Copy testdata/audit.log to the temp directory
	data, err := os.ReadFile("testdata/audit.log")
	assert.NoError(t, err)
	err = os.WriteFile(logFile, data, 0644)
	assert.NoError(t, err)

	go processor.StartProcessingJob()

	time.Sleep(2 * time.Second) // Give it time to process

	err = processor.Stop(context.Background())
	assert.NoError(t, err)

	assert.Len(t, logs, 4, "Expected four logs to be processed")
	assert.Equal(t, "EcNxIrskXYJttXoioLH", logs[0].Transaction.ID)
}

func TestProcessLogFileSummarizesFailures(t *testing.T) {
	tempDir := t.TempDir()
	logFile := path.Join(tempDir, "audit.log")

	content := `{"transaction":{"id":"ok"},"messages":[{"data":{"id":1}}]}

not json
{"transaction":{"id":"fail"},"messages":[{"data":{"id":2}}]}
`
	err := os.WriteFile(logFile, []byte(content), 0644)
	assert.NoError(t, err)

	var buf bytes.Buffer
	processor := NewLogProcessor(AuditLogProcessorOptions{AuditLogPath: logFile})
	processor.logger = slog.New(slog.NewJSONHandler(&buf, nil))
	processor.logHandler = func(l Log) error {
		if l.Transaction.ID == "fail" {
			return errors.New("handler failed")
		}
		return nil
	}

	// Per-entry failures are summarized rather than returned
	err = processor.ProcessLogFile(logFile)
	assert.NoError(t, err)

	var summary map[string]any
	err = json.Unmarshal(buf.Bytes(), &summary)
	assert.NoError(t, err, "Expected a single summary log line")
	assert.Equal(t, "WARN", summary["level"])
	assert.EqualValues(t, 3, summary["entries"], "Expected blank lines to be skipped")
	assert.EqualValues(t, 1, summary["violations"], "Expected only successfully handled violations to be counted")
	assert.EqualValues(t, 1, summary["parse_errors"])
	assert.EqualValues(t, 1, summary["handler_errors"])
	assert.Contains(t, summary["first_error"], "failed to parse log entry")
}

func TestProcessLogFileAllEntriesFailed(t *testing.T) {
	tempDir := t.TempDir()
	logFile := path.Join(tempDir, "audit.log")

	err := os.WriteFile(logFile, []byte("not json\nalso not json\n"), 0644)
	assert.NoError(t, err)

	var buf bytes.Buffer
	processor := NewLogProcessor(AuditLogProcessorOptions{AuditLogPath: logFile})
	processor.logger = slog.New(slog.NewJSONHandler(&buf, nil))

	err = processor.ProcessLogFile(logFile)
	assert.NoError(t, err)

	var summary map[string]any
	err = json.Unmarshal(buf.Bytes(), &summary)
	assert.NoError(t, err, "Expected a single summary log line")
	assert.Equal(t, "ERROR", summary["level"])
	assert.EqualValues(t, 2, summary["parse_errors"])
}

func TestRotateAuditLogs(t *testing.T) {
	tempDir := t.TempDir()
	logFile := path.Join(tempDir, "audit.log")

	processor := NewLogProcessor(AuditLogProcessorOptions{
		AuditLogPath: logFile,
	})

	// Check if audit logs exist (they shouldn't initially)
	exist, err := processor.checkIfLogsExist()
	assert.NoError(t, err)
	assert.False(t, exist, "Expected no audit logs initially")

	// Create a dummy audit log file to simulate existing logs
	logPath := path.Join(tempDir, "audit.log")
	err = os.WriteFile(logPath, []byte("dummy log content"), 0644)
	assert.NoError(t, err)

	// Check again if audit logs exist (they should now)
	exist, err = processor.checkIfLogsExist()
	assert.NoError(t, err)
	assert.True(t, exist, "Expected audit logs to exist after creation")

	// Rotate the audit logs
	rotatedLogPath, err := processor.rotateLogs()
	assert.NoError(t, err)
	assert.NotEmpty(t, rotatedLogPath, "Expected rotated log path to be non-empty")

	// Verify that the rotated log file exists
	_, err = os.Stat(rotatedLogPath)
	assert.NoError(t, err, "Expected rotated log file to exist")

	// Verify that the original log file has been truncated
	info, err := os.Stat(logPath)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), info.Size(), "Expected original log file to be truncated")
}

func TestRotateAuditLogsConcurrently(t *testing.T) {
	tempDir := t.TempDir()
	logFile := path.Join(tempDir, "audit.log")

	// Create a dummy audit log file to simulate existing logs
	err := os.WriteFile(logFile, []byte("dummy log content"), 0644)
	assert.NoError(t, err)

	// Rotate the audit logs concurrently
	const numRoutines = 3
	processor := NewLogProcessor(AuditLogProcessorOptions{
		AuditLogPath: logFile,
	})
	errCh := make(chan error, numRoutines)
	for i := 0; i < numRoutines; i++ {
		go func() {
			_, err := processor.rotateLogs()
			errCh <- err
		}()
	}

	// Collect errors from all goroutines
	for i := 0; i < numRoutines; i++ {
		err := <-errCh
		assert.NoError(t, err, "Expected no error during concurrent rotation")
	}

	// Verify that the original log file has been truncated
	info, err := os.Stat(logFile)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), info.Size(), "Expected original log file to be truncated")
}

func TestLogExpiration(t *testing.T) {
	tempDir := t.TempDir()
	logFile := path.Join(tempDir, "audit.log")

	processor := NewLogProcessor(AuditLogProcessorOptions{
		AuditLogPath:          logFile,
		ExpirationJobInterval: time.Second,
		LogExpiration:         time.Minute,
	})

	// Create dummy log files with different modification times
	oldBackupFilename := processor.generateNewBackupFilename(time.Now().Add(-1 * time.Hour))
	recentBackupFilename := processor.generateNewBackupFilename(time.Now())
	err := os.WriteFile(oldBackupFilename, []byte("old log content"), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(recentBackupFilename, []byte("recent log content"), 0644)
	assert.NoError(t, err)

	go processor.StartExpirationJob()

	time.Sleep(2 * time.Second) // Give it time to expire old logs

	err = processor.Stop(context.Background())
	assert.NoError(t, err)

	// Verify that the old log file has been deleted
	_, err = os.Stat(oldBackupFilename)
	assert.True(t, os.IsNotExist(err), "Expected old log file to be deleted")

	// Verify that the recent log file still exists
	_, err = os.Stat(recentBackupFilename)
	assert.NoError(t, err, "Expected recent log file to still exist")
}
