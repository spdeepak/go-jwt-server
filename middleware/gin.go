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
			Any("extra", map[string]interface{}{
				"method":     c.Request.Method,
				"path":       c.Request.URL.Path,
				"status":     statusCode,
				"latency_ms": latency,
				"client_ip":  c.ClientIP(),
				"user_agent": c.Request.UserAgent(),
			})

		if len(c.Errors) > 0 {
			logEvent.Str("errors", c.Errors.String())
		}
		logEvent.Msg("HTTP request")
	}
}
