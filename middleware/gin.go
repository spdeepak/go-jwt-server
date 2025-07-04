package middleware

import (
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

var IgnorePaths = []string{
	"/live",
	"/ready",
}

// GinLogger is the middleware function that uses zerolog for logging
func GinLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		if slices.Contains(IgnorePaths, c.Request.URL.Path) {
			return // ignore
		}

		startTime := time.Now()
		c.Next()
		endTime := time.Now()
		latency := endTime.Sub(startTime).Milliseconds()
		statusCode := c.Writer.Status()

		logEvent := log.Debug().
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Int("status", statusCode).
			Int64("latency_ms", latency).
			Str("client_ip", c.ClientIP()).
			Str("user_agent", c.Request.UserAgent())

		if len(c.Errors) > 0 {
			logEvent.Str("errors", c.Errors.String())
		}
		logEvent.Msg("HTTP request")
	}
}
