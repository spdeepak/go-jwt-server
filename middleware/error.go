package middleware

import (
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
		}
	}()
	c.Next()
}
