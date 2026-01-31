package middleware

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/spdeepak/go-jwt-server/internal/error"
	"github.com/spdeepak/go-jwt-server/internal/tokens"
	"github.com/spdeepak/go-jwt-server/util"
)

var (
	authSuccess = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "go_jwt_server_auth_success_total",
			Help: "Total number of successful authentication attempts",
		},
	)
	authFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "go_jwt_server_auth_failures_total",
			Help: "Total number of failed authentication attempts, labeled by reason",
		},
		[]string{"reason"},
	)
)

func init() {
	prometheus.MustRegister(authFailures, authSuccess)
}

// JWTAuthMiddleware returns a middleware that checks for a valid JWT token, but skips any paths listed in skipPaths.
func JWTAuthMiddleware(secret []byte, skipPaths []string, issuer string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		if slices.Contains(append([]string{"/ready", "/live", "/api/v1/auth/signup", "/api/v1/auth/login"}, skipPaths...), path) {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			authFailures.WithLabelValues("MissingToken").Inc()
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				httperror.HttpError{
					Description: "Missing or invalid Authorization header",
					StatusCode:  http.StatusUnauthorized,
				})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.ParseWithClaims(
			tokenStr,
			&tokens.TokenClaims{},
			func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrTokenUnverifiable
				}
				return secret, nil
			},
			jwt.WithIssuer(issuer),
		)

		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				authFailures.WithLabelValues("ExpiredToken").Inc()
				c.AbortWithStatusJSON(http.StatusUnauthorized, httperror.HttpError{
					Description: jwt.ErrTokenExpired.Error(),
					StatusCode:  http.StatusUnauthorized,
				})
				return
			}
			authFailures.WithLabelValues("Unauthorized").Inc()
			c.AbortWithStatusJSON(http.StatusUnauthorized, httperror.HttpError{
				Description: err.Error(),
				StatusCode:  http.StatusUnauthorized,
			})
			return
		}

		if !token.Valid {
			authFailures.WithLabelValues("Unauthorized").Inc()
			c.AbortWithStatusJSON(http.StatusUnauthorized, httperror.HttpError{
				Description: "Unauthorized",
				StatusCode:  http.StatusUnauthorized,
			})
			return
		}
		claims, ok := token.Claims.(*tokens.TokenClaims)
		if !ok {
			authFailures.WithLabelValues("ClaimsMissing").Inc()
			c.AbortWithStatusJSON(http.StatusUnauthorized, httperror.HttpError{
				Description: jwt.ErrTokenInvalidClaims.Error(),
				Metadata:    jwt.ErrTokenRequiredClaimMissing.Error(),
				StatusCode:  http.StatusUnauthorized,
			})
			return
		}
		if endpointAuthPolicy, endpointAuthPolicyExists := c.Get(aegisAuth); endpointAuthPolicyExists {
			if !endpointAuthPolicy.(*authPolicy).evalAnyOf(claims.Roles, claims.Permissions, false) {
				authFailures.WithLabelValues("RolesAndPermissionsMissing").Inc()
				c.AbortWithStatusJSON(http.StatusUnauthorized, httperror.HttpError{
					Description: jwt.ErrTokenRequiredClaimMissing.Error(),
					Metadata:    "Roles and Permissions Missing",
					StatusCode:  http.StatusUnauthorized,
				})
				return
			}
		}
		if claims.Subject == "" {
			authFailures.WithLabelValues("RequiredClaimsMissing").Inc()
			c.AbortWithStatusJSON(http.StatusUnauthorized, httperror.HttpError{
				Description: jwt.ErrTokenInvalidClaims.Error(),
				Metadata:    jwt.ErrTokenRequiredClaimMissing.Error(),
				StatusCode:  http.StatusUnauthorized,
			})
			return
		}
		userId, err := uuid.Parse(claims.Subject)
		if err != nil {
			authFailures.WithLabelValues("RequiredClaimsMissing").Inc()
			c.AbortWithStatusJSON(http.StatusUnauthorized, httperror.HttpError{
				Description: jwt.ErrTokenInvalidClaims.Error(),
				Metadata:    jwt.ErrTokenRequiredClaimMissing.Error(),
				StatusCode:  http.StatusUnauthorized,
			})
			return
		}
		switch claims.Type {
		case "2FA":
			c.Set("User-ID", userId)
		case "Bearer", "Refresh":
			c.Set("User-ID", userId)
			c.Set("User-Email", claims.Email)
		default:
			authFailures.WithLabelValues("RequiredClaimsMissing").Inc()
			c.AbortWithStatusJSON(http.StatusUnauthorized, httperror.HttpError{
				Description: jwt.ErrTokenInvalidClaims.Error(),
				Metadata:    jwt.ErrTokenRequiredClaimMissing.Error(),
				StatusCode:  http.StatusUnauthorized,
			})
			return
		}

		c.Set("user-ip", c.ClientIP())
		c.Set("user", token.Claims)
		authSuccess.Inc()
		c.Next()
	}
}

type (
	authPolicy struct {
		AnyOf of   `json:"anyOf,omitempty"`
		AllOf of   `json:"allOf,omitempty"`
		Self  bool `json:"self,omitempty"`
	}
	of struct {
		Roles       []string `json:"roles,omitempty"`
		Permissions []string `json:"permissions,omitempty"`
	}
)

func (a *authPolicy) evalAnyOf(userRoles []string, userPerms []string, isSelf bool) bool {
	// If nothing is specified, allow
	if (a.AnyOf.Roles == nil || len(a.AnyOf.Roles) == 0) &&
		(a.AnyOf.Permissions == nil || len(a.AnyOf.Permissions) == 0) &&
		!a.Self {
		return true
	}

	// Check if self matches
	if a.Self && isSelf {
		return true
	}

	// Check if any role matches
	if a.AnyOf.Roles != nil && util.HasAny(a.AnyOf.Roles, userRoles) {
		return true
	}

	// Check if any permission matches
	if a.AnyOf.Permissions != nil && util.HasAny(a.AnyOf.Permissions, userPerms) {
		return true
	}

	// None matched
	return false
}
