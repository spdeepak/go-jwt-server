//go:build test

package logging

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type capturedRecord struct {
	Time    time.Time
	Level   slog.Level
	Message string
	Attrs   map[string]string
}

type mockHandler struct {
	records []capturedRecord
}

func (m *mockHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (m *mockHandler) Handle(_ context.Context, r slog.Record) error {
	captured := capturedRecord{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
		Attrs:   make(map[string]string),
	}
	r.Attrs(func(a slog.Attr) bool {
		captured.Attrs[a.Key] = a.Value.String()
		return true
	})
	m.records = append(m.records, captured)
	return nil
}

func (m *mockHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return m
}

func (m *mockHandler) WithGroup(_ string) slog.Handler {
	return m
}

func TestNewHandler(t *testing.T) {
	t.Parallel()

	mock := &mockHandler{}
	h := NewHandler(mock)

	require.NotNil(t, h)
}

func TestNewDefaultHandler(t *testing.T) {
	t.Parallel()

	h := NewDefaultHandler()

	require.NotNil(t, h)
}

func TestHandler_Handle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		setupContext   func() context.Context
		expectedExtras map[string]interface{}
	}{
		{
			name: "empty context",
			setupContext: func() context.Context {
				return context.Background()
			},
			expectedExtras: map[string]interface{}{},
		},
		{
			name: "context with correlation id",
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), CorrelationIdHeader, "test-correlation-123")
			},
			expectedExtras: map[string]interface{}{
				CorrelationIdHeader: "test-correlation-123",
			},
		},
		{
			name: "context with agent name",
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), AgentNameHeader, "test-agent")
			},
			expectedExtras: map[string]interface{}{
				AgentNameHeader: "test-agent",
			},
		},
		{
			name: "context with user email",
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), UserEmailHeader, "user@example.com")
			},
			expectedExtras: map[string]interface{}{
				UserEmailHeader: "user@example.com",
			},
		},
		{
			name: "context with all headers",
			setupContext: func() context.Context {
				ctx := context.WithValue(context.Background(), CorrelationIdHeader, "corr-456")
				ctx = context.WithValue(ctx, AgentNameHeader, "my-agent")
				ctx = context.WithValue(ctx, UserEmailHeader, "test@test.com")
				return ctx
			},
			expectedExtras: map[string]interface{}{
				CorrelationIdHeader: "corr-456",
				AgentNameHeader:     "my-agent",
				UserEmailHeader:     "test@test.com",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := &mockHandler{}
			h := NewHandler(mock)
			ctx := tt.setupContext()

			record := slog.NewRecord(time.Now(), slog.LevelInfo, "test message", 0)
			err := h.Handle(ctx, record)

			require.NoError(t, err)
			require.Len(t, mock.records, 1)

			extraStr := mock.records[0].Attrs["extra"]
			var extra map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(extraStr), &extra))

			assert.Equal(t, tt.expectedExtras, extra)
		})
	}
}

func TestHandler_Handle_WithGinContext(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		headers        map[string]string
		expectedExtras map[string]interface{}
	}{
		{
			name:           "gin context without headers",
			headers:        map[string]string{},
			expectedExtras: map[string]interface{}{},
		},
		{
			name: "gin context with agent name header",
			headers: map[string]string{
				AgentNameHeader: "gin-agent",
			},
			expectedExtras: map[string]interface{}{
				AgentNameHeader: "gin-agent",
			},
		},
		{
			name: "gin context with user email header",
			headers: map[string]string{
				UserEmailHeader: "gin-user@example.com",
			},
			expectedExtras: map[string]interface{}{
				UserEmailHeader: "gin-user@example.com",
			},
		},
		{
			name: "gin context with both headers",
			headers: map[string]string{
				AgentNameHeader: "gin-agent-2",
				UserEmailHeader: "gin-user2@example.com",
			},
			expectedExtras: map[string]interface{}{
				AgentNameHeader: "gin-agent-2",
				UserEmailHeader: "gin-user2@example.com",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := &mockHandler{}
			h := NewHandler(mock)

			w := httptest.NewRecorder()
			ginCtx, _ := gin.CreateTestContext(w)
			ginCtx.Request = httptest.NewRequest("GET", "/test", nil)
			for k, v := range tt.headers {
				ginCtx.Request.Header.Set(k, v)
			}

			record := slog.NewRecord(time.Now(), slog.LevelInfo, "test message", 0)
			err := h.Handle(ginCtx, record)

			require.NoError(t, err)
			require.Len(t, mock.records, 1)

			extraStr := mock.records[0].Attrs["extra"]
			var extra map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(extraStr), &extra))

			assert.Equal(t, tt.expectedExtras, extra)
		})
	}
}

func TestHandler_Handle_WithRecordAttributes(t *testing.T) {
	t.Parallel()

	mock := &mockHandler{}
	h := NewHandler(mock)

	record := slog.NewRecord(time.Now(), slog.LevelInfo, "test message", 0)
	record.AddAttrs(
		slog.String("key1", "value1"),
		slog.Int("key2", 42),
		slog.Bool("key3", true),
	)

	err := h.Handle(context.Background(), record)

	require.NoError(t, err)
	require.Len(t, mock.records, 1)

	extraStr := mock.records[0].Attrs["extra"]
	var extra map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(extraStr), &extra))

	assert.Equal(t, "value1", extra["key1"])
	assert.Equal(t, float64(42), extra["key2"])
	assert.Equal(t, true, extra["key3"])
}

func TestHandler_Handle_ContextOverridesRecordAttrs(t *testing.T) {
	t.Parallel()

	mock := &mockHandler{}
	h := NewHandler(mock)

	ctx := context.WithValue(context.Background(), CorrelationIdHeader, "context-correlation")

	record := slog.NewRecord(time.Now(), slog.LevelInfo, "test message", 0)
	record.AddAttrs(slog.String(CorrelationIdHeader, "record-correlation"))

	err := h.Handle(ctx, record)

	require.NoError(t, err)
	require.Len(t, mock.records, 1)

	extraStr := mock.records[0].Attrs["extra"]
	var extra map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(extraStr), &extra))

	assert.Equal(t, "context-correlation", extra[CorrelationIdHeader])
}

func TestGetLogLevelFromEnv(t *testing.T) {
	tests := []struct {
		name          string
		envValue      string
		expectedLevel slog.Level
	}{
		{
			name:          "DEBUG level",
			envValue:      "DEBUG",
			expectedLevel: slog.LevelDebug,
		},
		{
			name:          "debug lowercase",
			envValue:      "debug",
			expectedLevel: slog.LevelDebug,
		},
		{
			name:          "INFO level",
			envValue:      "INFO",
			expectedLevel: slog.LevelInfo,
		},
		{
			name:          "info lowercase",
			envValue:      "info",
			expectedLevel: slog.LevelInfo,
		},
		{
			name:          "WARN level",
			envValue:      "WARN",
			expectedLevel: slog.LevelWarn,
		},
		{
			name:          "warn lowercase",
			envValue:      "warn",
			expectedLevel: slog.LevelWarn,
		},
		{
			name:          "ERROR level",
			envValue:      "ERROR",
			expectedLevel: slog.LevelError,
		},
		{
			name:          "error lowercase",
			envValue:      "error",
			expectedLevel: slog.LevelError,
		},
		{
			name:          "empty defaults to INFO",
			envValue:      "",
			expectedLevel: slog.LevelInfo,
		},
		{
			name:          "invalid defaults to INFO",
			envValue:      "INVALID",
			expectedLevel: slog.LevelInfo,
		},
		{
			name:          "mixed case Debug",
			envValue:      "DeBuG",
			expectedLevel: slog.LevelDebug,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalValue := os.Getenv("LOG_LEVEL")
			defer os.Setenv("LOG_LEVEL", originalValue)

			os.Setenv("LOG_LEVEL", tt.envValue)

			level := GetLogLevelFromEnv()

			assert.Equal(t, tt.expectedLevel, level)
		})
	}
}
