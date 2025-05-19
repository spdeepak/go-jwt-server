package httperror

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func Middleware(c *gin.Context) {
	defer func() {
		if err := recover(); err != nil {
			log.Ctx(c).Error().Any("error", err).Str("path", c.Request.URL.Path).Msg("Panic occurred")
			// Respond with an error to the client
			c.AbortWithStatusJSON(
				http.StatusInternalServerError,
				HttpError{
					Description: "Internal error",
					ErrorCode:   "500",
					Metadata:    fmt.Sprintf("%v", err),
					StatusCode:  http.StatusInternalServerError,
				},
			)
		} else {
			for _, err := range c.Errors {
				var e HttpError
				switch {
				case errors.As(err.Err, &e):
					if e.StatusCode >= 400 && e.StatusCode < 500 {
						logWarning(c, err)
					} else {
						logError(c, err)
					}
					c.AbortWithStatusJSON(e.StatusCode, e)
				default:
					logError(c, err)
					c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]string{"message": "Service Unavailable"})
				}
			}
		}
	}()
	c.Next()
}

func logError(c *gin.Context, err *gin.Error) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(c.Request.Body)
	log.Ctx(c).Error().Any("error", err).Any("requestBody", buf.String()).Str("path", c.Request.URL.Path).
		Send()
}

func logWarning(c *gin.Context, err *gin.Error) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(c.Request.Body)
	log.Ctx(c).Warn().Any("error", err).Any("requestBody", buf.String()).Str("path", c.Request.URL.Path).
		Send()
}

func logDebug(c *gin.Context, err *gin.Error) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(c.Request.Body)
	log.Ctx(c).Debug().Any("error", err).Any("requestBody", buf.String()).Str("path", c.Request.URL.Path).
		Send()
}
