package jwt_secret

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/jwt_secret/repository"
)

type service struct {
	secret  []byte
	storage Storage
}

type Service interface {
	VerifyRefreshToken(token string) (*jwt.Token, jwt.MapClaims, error)
	GenerateTokenPair(ctx *gin.Context, user repository.User) (api.LoginResponse, error)
}

func GetSecret(storage Storage) []byte {
	secret, present := os.LookupEnv("JWT_TOKEN_SECRET")
	if !present {
		secret, _ = storage.getOrCreateDefaultSecret(context.Background(), generateJWTSecret())
		log.Warn().Msgf("JWT_TOKEN_SECRET not provided. A new secret was generated and stored in the database.")
	}
	return []byte(secret)
}

func NewService(storage Storage) Service {
	secret, present := os.LookupEnv("JWT_TOKEN_SECRET")
	if !present {
		secret, _ = storage.getOrCreateDefaultSecret(context.Background(), generateJWTSecret())
		log.Warn().Msgf("JWT_TOKEN_SECRET not provided. A new secret was generated and stored in the database.")
	}
	return &service{
		secret:  []byte(secret),
		storage: storage,
	}
}

func (s *service) GenerateTokenPair(ctx *gin.Context, user repository.User) (api.LoginResponse, error) {
	accessTokenClaims := jwt.MapClaims{
		"name":       user.FirstName + " " + user.LastName,
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"typ":        "Bearer",                                //Type of token
		"nbf":        time.Now().Unix(),                       //Not valid before
		"iss":        "go-jwt-server",                         //Issuer
		"iat":        time.Now().Unix(),                       //Issued at
		"jti":        uuid.NewString(),                        //JWT ID
		"exp":        time.Now().Add(15 * time.Minute).Unix(), //Expiration time
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	signedAccessToken, err := accessToken.SignedString(s.secret)
	if err != nil {
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}

	refreshTokenClaims := jwt.MapClaims{
		"email": user.Email,
		"typ":   "Refresh",                                 //Type of token
		"nbf":   time.Now().Unix(),                         //Not valid before
		"iss":   "go-jwt-server",                           //Issuer
		"iat":   time.Now().Unix(),                         //Issued at
		"jti":   uuid.NewString(),                          //JWT ID
		"exp":   time.Now().Add(7 * 24 * time.Hour).Unix(), //Expiration time
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	signedRefreshToken, err := refreshToken.SignedString(s.secret)
	if err != nil {
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}

	return api.LoginResponse{
		AccessToken:  signedAccessToken,
		RefreshToken: signedRefreshToken,
	}, nil
}

func (s *service) VerifyRefreshToken(tokenStr string) (*jwt.Token, jwt.MapClaims, error) {
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

func generateJWTSecret() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal().Msgf("JWT_TOKEN_SECRET is not set. Failed to generate default JWT secret : %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}
