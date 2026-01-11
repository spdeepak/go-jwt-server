package middleware

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/gin-gonic/gin"
	ginmiddleware "github.com/oapi-codegen/gin-middleware"

	httperror "github.com/spdeepak/go-jwt-server/internal/error"
)

var IgnorePaths = []string{
	"/live",
	"/ready",
}

// GinLogger is the middleware function that uses slog for logging
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

		logEvent := slog.Any("extra", map[string]interface{}{
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"status":     statusCode,
			"latency_ms": latency,
			"client_ip":  c.ClientIP(),
			"user_agent": c.Request.UserAgent(),
		})

		if len(c.Errors) > 0 {
			slog.Error("errors", c.Errors.String(), logEvent)
		}
		slog.Info("HTTP request", logEvent)
	}
}

func RequestValidator(swagger *openapi3.T) gin.HandlerFunc {
	authFunc := func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
		if input.SecuritySchemeName != "bearerAuth" {
			return nil
		}
		authHeader := input.RequestValidationInput.Request.Header.Get("Authorization")
		if authHeader == "" {
			return errors.New("no authorization header")
		}
		return nil
	}
	return ginmiddleware.OapiRequestValidatorWithOptions(swagger, &ginmiddleware.Options{
		ErrorHandler: func(c *gin.Context, message string, statusCode int) {
			c.AbortWithStatusJSON(statusCode, httperror.HttpError{
				Description: message,
				StatusCode:  statusCode,
			})
		},
		Options: openapi3filter.Options{
			AuthenticationFunc: authFunc,
		},
	})
}
