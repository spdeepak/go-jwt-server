package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gin-gonic/gin"
	ginmiddleware "github.com/oapi-codegen/gin-middleware"
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

func OpenApiErrors(swagger *openapi3.T) gin.HandlerFunc {
	return ginmiddleware.OapiRequestValidatorWithOptions(swagger, &ginmiddleware.Options{
		ErrorHandler: func(c *gin.Context, message string, statusCode int) {
			body, _ := io.ReadAll(c.Request.Body)
			log.Ctx(c).Debug().Any("error", message).Any("requestBody", string(body)).Str("path", c.Request.URL.Path).Send()
			c.AbortWithStatusJSON(statusCode, httperror.HttpError{
				StatusCode:  statusCode,
				Description: message,
			})
		},
	})
}
