package middleware

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/spdeepak/go-jwt-server/internal/error"
)

func ErrorMiddleware(c *gin.Context) {
	defer func() {
		if err := recover(); err != nil {
			slog.ErrorContext(c, "Panic occurred", slog.Any("error", err), slog.String("path", c.Request.URL.Path))
			// Respond with an error to the client
			c.AbortWithStatusJSON(
				http.StatusInternalServerError,
				httperror.HttpError{
					Description: "Internal error",
					ErrorCode:   "500",
					Metadata:    fmt.Sprintf("%v", err),
					StatusCode:  http.StatusInternalServerError,
				},
			)
		} else {
			for _, er := range c.Errors {
				var e httperror.HttpError
				switch {
				case errors.As(er.Err, &e):
					if e.StatusCode >= 400 && e.StatusCode < 500 {
						logWarning(c, er)
					} else {
						logError(c, er)
					}
					c.AbortWithStatusJSON(e.StatusCode, e)
				default:
					logError(c, er)
					c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]string{"message": "Service Unavailable"})
				}
			}
		}
	}()
	c.Next()
}

func logError(c *gin.Context, err *gin.Error) {
	slog.ErrorContext(c, "", slog.Any("error", err), slog.String("path", c.Request.URL.Path))
}

func logWarning(c *gin.Context, err *gin.Error) {
	slog.WarnContext(c, "", slog.Any("error", err), slog.String("path", c.Request.URL.Path))
}

func logDebug(c *gin.Context, err *gin.Error) {
	slog.DebugContext(c, "", slog.Any("error", err), slog.String("path", c.Request.URL.Path))
}
