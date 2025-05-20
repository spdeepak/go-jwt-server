package tokens

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/tokens/repository"
)

type service struct {
	secret  []byte
	storage Storage
}

type TokenParams struct {
	XLoginSource string
	UserAgent    string
}

type Service interface {
	VerifyRefreshToken(ctx *gin.Context, token string) (*jwt.Token, jwt.MapClaims, error)
	GenerateTokenPair(ctx *gin.Context, params TokenParams, user repository.User) (api.LoginResponse, error)
	RevokeRefreshToken(ctx *gin.Context, params api.RevokeRefreshTokenParams, refresh api.RevokeRefresh) error
}

func NewService(storage Storage, secret []byte) Service {
	return &service{
		secret:  secret,
		storage: storage,
	}
}

func (s *service) GenerateTokenPair(ctx *gin.Context, params TokenParams, user repository.User) (api.LoginResponse, error) {
	now := time.Now()
	accessClaims := bearerTokenClaims(user, now)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccessToken, err := accessToken.SignedString(s.secret)
	if err != nil {
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}

	refreshClaims := refreshTokenClaims(user, now)
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
	token, err := jwt.ParseWithClaims(authHeader, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, httperror.NewWithMetadata(httperror.UndefinedErrorCode, fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
		}
		return s.secret, nil
	})

	if err != nil {
		// could be expired, malformed, or invalid signature
		return err
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

func (s *service) VerifyRefreshToken(ctx *gin.Context, tokenStr string) (*jwt.Token, jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, httperror.NewWithMetadata(httperror.UndefinedErrorCode, fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
		}
		return s.secret, nil
	})

	if err != nil {
		return nil, nil, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	} else if !token.Valid {
		return nil, nil, httperror.New(httperror.UndefinedErrorCode)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, httperror.NewWithMetadata(httperror.UndefinedErrorCode, "invalid claims")
	}

	return token, claims, nil
}

func (s *service) RevokeRefreshToken(ctx *gin.Context, params api.RevokeRefreshTokenParams, refresh api.RevokeRefresh) error {
	hashedRefreshToken := hashToken(refresh.RefreshToken)
	err := s.storage.revokeRefreshToken(ctx, hashedRefreshToken)
	if err != nil {
		return nil
	}
	return nil
}

func bearerTokenClaims(user repository.User, now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"name":       user.FirstName + " " + user.LastName,
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"typ":        "Bearer",                         //Type of token
		"nbf":        now.Unix(),                       //Not valid before
		"iss":        "go-jwt-server",                  //Issuer
		"iat":        now.Unix(),                       //Issued at
		"jti":        uuid.NewString(),                 //JWT ID
		"exp":        now.Add(15 * time.Minute).Unix(), //Expiration now
	}
}

func refreshTokenClaims(user repository.User, now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"email": user.Email,
		"typ":   "Refresh",                          //Type of token
		"nbf":   now.Unix(),                         //Not valid before
		"iss":   "go-jwt-server",                    //Issuer
		"iat":   now.Unix(),                         //Issued at
		"jti":   uuid.NewString(),                   //JWT ID
		"exp":   now.Add(7 * 24 * time.Hour).Unix(), //Expiration now
	}
}

func hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}
