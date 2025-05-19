package jwt_secret

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"github.com/spdeepak/go-jwt-server/api"
)

type service struct {
	secret  []byte
	storage Storage
}

type Service interface {
	GenerateTokenPair(email string) (api.LoginResponse, error)
	VerifyToken(tokenStr string) (*jwt.Token, jwt.MapClaims, error)
}

func NewService(storage Storage) Service {
	secret, present := os.LookupEnv("JWT_TOKEN_SECRET")
	if !present {
		log.Warn().Msgf("JWT_TOKEN_SECRET not provided. A new secret was generated and stored in the database.")
		secret, _ = storage.GetOrCreateDefaultSecret(context.Background(), generateJWTSecret())
	}
	return &service{
		secret:  []byte(secret),
		storage: storage,
	}
}

func (t *service) GenerateTokenPair(email string) (api.LoginResponse, error) {
	accessTokenClaims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	signedAccessToken, err := accessToken.SignedString(t.secret)
	if err != nil {
		return api.LoginResponse{}, err
	}

	refreshTokenClaims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(7 * 24 * time.Hour).Unix(),
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	signedRefreshToken, err := refreshToken.SignedString(t.secret)
	if err != nil {
		return api.LoginResponse{}, err
	}

	return api.LoginResponse{
		AccessToken:  signedAccessToken,
		RefreshToken: signedRefreshToken,
	}, nil
}

func (t *service) VerifyToken(tokenStr string) (*jwt.Token, jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return t.secret, nil
	})

	if err != nil || !token.Valid {
		return nil, nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, errors.New("invalid claims")
	}

	return token, claims, nil
}

func generateJWTSecret() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Panic().Msgf("Failed to generate JWT secret: %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}
