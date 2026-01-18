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
		latency := time.Since(startTime).Milliseconds()

		var logEvents []slog.Attr
		logEvents = append(logEvents, slog.Any("method", c.Request.Method))
		logEvents = append(logEvents, slog.Any("path", c.Request.URL.Path))
		logEvents = append(logEvents, slog.Any("status", c.Writer.Status()))
		logEvents = append(logEvents, slog.Any("latency_ms", latency))
		logEvents = append(logEvents, slog.Any("client_ip", c.ClientIP()))
		logEvents = append(logEvents, slog.Any("user_agent", c.Request.UserAgent()))

		if len(c.Errors) > 0 {
			slog.ErrorContext(c, "errors", c.Errors.String(), slog.GroupValue(logEvents...))
		} else {
			slog.InfoContext(c, "HTTP request", slog.Any("trace", slog.GroupValue(logEvents...)))
		}
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
