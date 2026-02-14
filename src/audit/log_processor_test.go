package audit

import (
	"context"
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
