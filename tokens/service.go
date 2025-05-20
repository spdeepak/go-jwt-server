package tokens

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/tokens/repository"
)

const (
	defaultBearerExpiry  = 15 * time.Minute
	defaultRefreshExpiry = 7 * 24 * time.Hour
)

type service struct {
	secret            []byte
	storage           Storage
	bearerExpiryTime  time.Duration
	refreshExpiryTime time.Duration
}

type TokenParams struct {
	XLoginSource string
	UserAgent    string
}

type Service interface {
	VerifyToken(ctx *gin.Context) error
	VerifyRefreshToken(ctx *gin.Context, token string) (jwt.MapClaims, error)
	GenerateTokenPair(ctx *gin.Context, params TokenParams, user repository.User) (api.LoginResponse, error)
	RevokeRefreshToken(ctx *gin.Context, params api.RevokeRefreshTokenParams, refresh api.RevokeRefresh) error
}

func NewService(storage Storage, secret []byte) Service {
	return &service{
		secret:            secret,
		storage:           storage,
		bearerExpiryTime:  getOrDefaultExpiry("BEARER_TOKEN_EXPIRY", defaultBearerExpiry),
		refreshExpiryTime: getOrDefaultExpiry("REFRESH_TOKEN_EXPIRY", defaultRefreshExpiry),
	}
}

func getOrDefaultExpiry(env string, defaultExpire time.Duration) time.Duration {
	expireDuration, expireDurationPresent := os.LookupEnv(env)
	if !expireDurationPresent {
		log.Warn().Msgf("%s not present, using default %s", env, defaultExpire)
		return defaultExpire
	} else if expiryTime, err := time.ParseDuration(expireDuration); err != nil {
		return expiryTime
	}
	return defaultExpire
}

func (s *service) GenerateTokenPair(ctx *gin.Context, params TokenParams, user repository.User) (api.LoginResponse, error) {
	now := time.Now()
	accessClaims := s.bearerTokenClaims(user, now)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccessToken, err := accessToken.SignedString(s.secret)
	if err != nil {
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}

	refreshClaims := s.refreshTokenClaims(user, now)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedRefreshToken, err := refreshToken.SignedString(s.secret)
	if err != nil {
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}
	saveTokenParams := repository.SaveTokenParams{
		Token:            hashToken(signedAccessToken),
		RefreshToken:     hashToken(signedRefreshToken),
		TokenExpiresAt:   time.Unix(accessClaims["exp"].(int64), 0),
		RefreshExpiresAt: time.Unix(refreshClaims["exp"].(int64), 0),
		IpAddress:        ctx.ClientIP(),
		UserAgent:        params.UserAgent,
		DeviceName:       "",
		CreatedBy:        params.XLoginSource,
	}
	err = s.storage.saveToken(ctx, saveTokenParams)
	if err != nil {
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.TokenCreationFailed, err.Error())
	}

	return api.LoginResponse{
		AccessToken:  signedAccessToken,
		RefreshToken: signedRefreshToken,
	}, nil
}

func (s *service) VerifyToken(ctx *gin.Context) error {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return httperror.New(httperror.Unauthorized)
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, httperror.NewWithMetadata(httperror.UndefinedErrorCode, fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
		}
		return s.secret, nil
	})

	if err != nil {
		return httperror.NewWithMetadata(httperror.Unauthorized, err.Error())
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
			return httperror.New(httperror.ExpiredBearerToken)
		}
		return nil
	} else if !ok || !token.Valid {
		return httperror.NewWithMetadata(httperror.UndefinedErrorCode, "invalid claims")
	}

	return nil
}

func (s *service) VerifyRefreshToken(ctx *gin.Context, tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, httperror.NewWithMetadata(httperror.UndefinedErrorCode, fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
		}
		return s.secret, nil
	})

	if err != nil {
		return nil, httperror.NewWithMetadata(httperror.Unauthorized, err.Error())
	} else if !token.Valid {
		return nil, httperror.NewWithMetadata(httperror.Unauthorized, "Invalid Refresh Token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		if expTime, ok := claims["exp"].(float64); ok {
			expirationTime := time.Unix(int64(expTime), 0)
			if expirationTime.Before(time.Now()) {
				return nil, httperror.New(httperror.ExpiredRefreshToken)
			}
		} else {
			return nil, httperror.NewWithMetadata(httperror.UndefinedErrorCode, "invalid claims")
		}
	} else if !ok || !token.Valid {
		return nil, httperror.NewWithMetadata(httperror.UndefinedErrorCode, "invalid claims")
	}

	return claims, nil
}

func (s *service) RevokeRefreshToken(ctx *gin.Context, params api.RevokeRefreshTokenParams, refresh api.RevokeRefresh) error {
	hashedRefreshToken := hashToken(refresh.RefreshToken)
	_, err := s.VerifyRefreshToken(ctx, refresh.RefreshToken)
	if err != nil {
		return err
	}
	err = s.storage.revokeRefreshToken(ctx, hashedRefreshToken)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return httperror.New(httperror.InvalidCredentials)
		}
		return httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}
	return nil
}

func (s *service) bearerTokenClaims(user repository.User, now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"name":       user.FirstName + " " + user.LastName,
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"typ":        "Bearer",                           //Type of token
		"nbf":        now.Unix(),                         //Not valid before
		"iss":        "go-jwt-server",                    //Issuer
		"iat":        now.Unix(),                         //Issued at
		"jti":        uuid.NewString(),                   //JWT ID
		"exp":        now.Add(s.bearerExpiryTime).Unix(), //Expiration now
	}
}

func (s *service) refreshTokenClaims(user repository.User, now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"email": user.Email,
		"typ":   "Refresh",                           //Type of token
		"nbf":   now.Unix(),                          //Not valid before
		"iss":   "go-jwt-server",                     //Issuer
		"iat":   now.Unix(),                          //Issued at
		"jti":   uuid.NewString(),                    //JWT ID
		"exp":   now.Add(s.refreshExpiryTime).Unix(), //Expiration now
	}
}

func hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}
