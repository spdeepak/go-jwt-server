package jwt_secret

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"

	"github.com/rs/zerolog/log"
)

func GetSecret(storage Storage) []byte {
	secret, present := os.LookupEnv("JWT_TOKEN_SECRET")
	if !present {
		secret, _ = storage.getOrCreateDefaultSecret(context.Background(), generateJWTSecret())
		log.Warn().Msgf("JWT_TOKEN_SECRET not provided. A new secret was generated and stored in the database.")
	}
	return []byte(secret)
}

func generateJWTSecret() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal().Msgf("JWT_TOKEN_SECRET is not set. Failed to generate default JWT secret : %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}
