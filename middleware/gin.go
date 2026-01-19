package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
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

		logAttributes := []any{
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.Int64("latency_ms", latency),
			slog.String("client_ip", c.ClientIP()),
		}

		if len(c.Errors) > 0 {
			for _, er := range c.Errors {
				var e httperror.HttpError
				switch {
				case errors.As(er.Err, &e):
					if e.StatusCode >= 400 && e.StatusCode < 500 {
						logWarning(c, er, logAttributes)
					} else {
						logError(c, er, logAttributes)
					}
					c.AbortWithStatusJSON(e.StatusCode, e)
				default:
					logError(c, er, logAttributes)
					c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]string{"message": "Service Unavailable"})
				}
			}
		} else {
			slog.InfoContext(c, "HTTP request", append(logAttributes, slog.String("path", c.Request.URL.Path))...)
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

func logError(c *gin.Context, err *gin.Error, logAttributes []any) {
	var httpErr httperror.HttpError
	if errors.As(err.Err, &httpErr) {
		slog.ErrorContext(c, httpErr.Description, append(logAttributes, slog.String("errorCode", httpErr.ErrorCode), slog.String("metadata", httpErr.Metadata), slog.Int("statusCode", httpErr.StatusCode))...)
	} else {
		slog.ErrorContext(c, "", append(logAttributes, slog.String("error", err.Error()), slog.String("path", c.Request.URL.Path))...)
	}
}

func logWarning(c *gin.Context, err *gin.Error, logAttributes []any) {
	var httpErr httperror.HttpError
	if errors.As(err.Err, &httpErr) {
		slog.WarnContext(c, httpErr.Description, append(logAttributes, slog.String("errorCode", httpErr.ErrorCode), slog.String("metadata", httpErr.Metadata), slog.Int("statusCode", httpErr.StatusCode))...)
	} else {
		slog.WarnContext(c, "", append(logAttributes, slog.String("error", err.Error()), slog.String("path", c.Request.URL.Path))...)
	}
}
