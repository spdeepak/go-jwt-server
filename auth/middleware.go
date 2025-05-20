package auth

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	httperror "github.com/spdeepak/go-jwt-server/error"
)

func AuthMiddlewareInline(c *gin.Context) error {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return httperror.New(httperror.Unauthorized)
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token != "valid-token" {
		return errors.New("invalid token")
	}

	return nil
}
