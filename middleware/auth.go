package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	httperror "github.com/spdeepak/go-jwt-server/error"
)

// JWTAuthMiddleware returns a middleware that checks for a valid JWT token,
// but skips any paths listed in skipPaths.
func JWTAuthMiddleware(secret []byte, skipPaths []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		for _, skip := range append([]string{"/ready", "/live", "/api/v1/auth/signup", "/api/v1/auth/login"}, skipPaths...) {
			if path == skip {
				c.Next()
				return
			}
		}

		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				httperror.HttpError{
					Description: "Missing or invalid Authorization header",
					StatusCode:  http.StatusUnauthorized,
				})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return secret, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				httperror.HttpError{
					Description: "Invalid Token",
					Metadata:    fmt.Sprintf("%v", err.Error()),
					StatusCode:  http.StatusUnauthorized,
				})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if ok && token.Valid {
			if expTime, ok := claims["exp"].(float64); ok {
				expirationTime := time.Unix(int64(expTime), 0)
				if expirationTime.Before(time.Now()) {
					c.AbortWithStatusJSON(http.StatusUnauthorized,
						httperror.HttpError{
							Description: jwt.ErrTokenExpired.Error(),
							Metadata:    fmt.Sprintf("%v", err.Error()),
							StatusCode:  http.StatusUnauthorized,
						})
					return
				}
			} else {
				c.AbortWithStatusJSON(http.StatusUnauthorized,
					httperror.HttpError{
						Description: jwt.ErrTokenInvalidClaims.Error(),
						Metadata:    fmt.Sprintf("%v", err.Error()),
						StatusCode:  http.StatusUnauthorized,
					})
				return
			}
		} else if !ok || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, httperror.HttpError{
				Description: jwt.ErrTokenInvalidClaims.Error(),
				Metadata:    fmt.Sprintf("%v", err.Error()),
				StatusCode:  http.StatusUnauthorized,
			})
			return
		}

		c.Set("user", token.Claims)
		c.Next()
	}
}
