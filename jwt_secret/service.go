package jwt_secret

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spdeepak/go-jwt-server/config"
)

func GetOrCreateSecret(token config.Token, storage Storage) []byte {
	base64EncodedEncryptedSecret, err := storage.getDefaultEncryptedSecret(context.Background())
	if err != nil {
		log.Fatal().Msg("Failed to get default secret from DB")
	}
	if base64EncodedEncryptedSecret != "" {
		if token.MasterKey != "" {
			secret, err := Decrypt(base64EncodedEncryptedSecret, token.MasterKey)
			if err != nil {
				log.Fatal().Msgf("Failed to decrypt JWT secret from DB. Error: %s", err.Error())
			}
			return secret
		} else {
			log.Fatal().Msg("JWT_MASTER_KEY not found to decrypt secret key")
		}
	}

	if token.MasterKey != "" {
		secret := generateJWTSecret()
		base64EncodedEncryptedSecret, err = Encrypt(secret, token.MasterKey)
		if err != nil {
			log.Fatal().Msgf("Failed to encrypt generated JWT secret and encode it to base64. Error: %s", err.Error())
		}
		err = storage.saveDefaultSecret(context.Background(), base64EncodedEncryptedSecret)
		if err != nil {
			log.Fatal().Msgf("Failed to save encrypted generated JWT secret to DB. Error: %s", err.Error())
		}
		return []byte(secret)
	}
	if token.Secret == "" {
		log.Fatal().Msg("Either JWT_MASTER_KEY or JWT_SECRET_KEY env variables should be set")
	}
	base64DecodedSecretKey, err := base64.StdEncoding.DecodeString(token.Secret)
	if err != nil {
		log.Fatal().Msgf("Failed to decode JWT_SECRET_KEY")
	}
	return base64DecodedSecretKey
}

func generateJWTSecret() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal().Msgf("JWT_TOKEN_SECRET is not set. Failed to generate default JWT secret : %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

// Encrypt takes the JWT secret and the JWT master key to encrypt the JWT secret. So, it can be stored to the DB.
func Encrypt(plainJwtSecret string, base64EncodedMasterKey string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(base64EncodedMasterKey)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plainJwtSecret), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt takes the encrypted JWT secret with the JWT master key to decrypt it for usage
func Decrypt(base64EncodedAndEncryptedSecret string, base64EncodedMasterKey string) ([]byte, error) {
	encryptedSecret, err := base64.StdEncoding.DecodeString(base64EncodedAndEncryptedSecret)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(base64EncodedMasterKey)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(encryptedSecret) < nonceSize {
		return nil, fmt.Errorf("invalid encryptedSecret")
	}

	nonce, ciphertext := encryptedSecret[:nonceSize], encryptedSecret[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	return plaintext, err
}
