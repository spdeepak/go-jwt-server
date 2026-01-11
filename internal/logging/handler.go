package logging

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	CorrelationIdHeader = "Correlation-Id"
	AgentNameHeader     = "User-Agent"
	UserEmailHeader     = "User-Email"
)

type handler struct {
	slog.Handler
}

func NewHandler(h slog.Handler) slog.Handler {
	return &handler{Handler: h}
}

func NewDefaultHandler() slog.Handler {
	opts := &slog.HandlerOptions{
		Level: GetLogLevelFromEnv(),
	}
	jsonHandler := slog.NewJSONHandler(os.Stdout, opts)
	return &handler{Handler: jsonHandler}
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	extra := make(map[string]interface{})
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "!BADKEY" || a.Value.Kind() == slog.KindGroup {
			attrs := a.Value.Group()
			for _, at := range attrs {
				extra[at.Key] = at.Value.String()
			}
		} else {
			extra[a.Key] = a.Value.Any()
		}
		return true
	})

	if correlationId := ctx.Value(CorrelationIdHeader); correlationId != nil {
		extra[CorrelationIdHeader] = correlationId.(string)
	}
	if agentName := ctx.Value(AgentNameHeader); agentName != nil {
		extra[AgentNameHeader] = agentName.(string)
	}
	if userEmailHeader := ctx.Value(UserEmailHeader); userEmailHeader != nil {
		extra[UserEmailHeader] = userEmailHeader.(string)
	}
	if ginCtx, ok := ctx.(*gin.Context); ok {
		agentName := ginCtx.Request.Header.Get(AgentNameHeader)
		userEmail := ginCtx.Request.Header.Get(UserEmailHeader)
		if len(agentName) > 0 {
			extra[AgentNameHeader] = agentName
		}
		if len(userEmail) > 0 {
			extra[UserEmailHeader] = userEmail
		}
	}

	newRecord := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	if extraJSON, err := json.Marshal(extra); err != nil {
		newRecord.AddAttrs(slog.String("extra", "{}"))
	} else {
		newRecord.AddAttrs(slog.String("extra", string(extraJSON)))
	}

	return h.Handler.Handle(ctx, newRecord)
}

func GetLogLevelFromEnv() slog.Level {
	logLevel := strings.ToUpper(os.Getenv("LOG_LEVEL"))
	switch logLevel {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
