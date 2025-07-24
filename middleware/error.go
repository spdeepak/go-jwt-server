package middleware

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	httperror "github.com/spdeepak/go-jwt-server/error"
)

func ErrorMiddleware(c *gin.Context) {
	defer func() {
		if err := recover(); err != nil {
			log.Ctx(c).Error().Any("error", err).Str("path", c.Request.URL.Path).Msg("Panic occurred")
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
	log.Ctx(c).Error().
		Any("error", err).
		Str("path", c.Request.URL.Path).
		Send()
}

func logWarning(c *gin.Context, err *gin.Error) {
	log.Ctx(c).Warn().
		Any("error", err).
		Str("path", c.Request.URL.Path).
		Send()
}

func logDebug(c *gin.Context, err *gin.Error) {
	log.Ctx(c).Debug().
		Any("error", err).
		Str("path", c.Request.URL.Path).
		Send()
}
