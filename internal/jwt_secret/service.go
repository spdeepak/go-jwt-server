package jwt_secret

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"

	"github.com/spdeepak/go-jwt-server/config"
)

func GetOrCreateSecret(token config.Token, storage Storage) []byte {
	base64EncodedEncryptedSecret, err := storage.getDefaultEncryptedSecret(context.Background())
	if err != nil {
		slog.Error("Failed to get default secret from DB")
		os.Exit(1)
	}
	if base64EncodedEncryptedSecret != "" {
		if token.MasterKey != "" {
			secret, err := Decrypt(base64EncodedEncryptedSecret, token.MasterKey)
			if err != nil {
				slog.Error("Failed to decrypt JWT secret from DB", slog.Any("error", err))
				os.Exit(1)
			}
			return secret
		} else {
			slog.Error("JWT_MASTER_KEY not found to decrypt secret key")
			os.Exit(1)
		}
	}

	if token.MasterKey != "" {
		secret := generateJWTSecret()
		base64EncodedEncryptedSecret, err = Encrypt(secret, token.MasterKey)
		if err != nil {
			slog.Error("Failed to encrypt generated JWT secret and encode it to base64", slog.Any("error", err))
			os.Exit(1)
		}
		err = storage.saveDefaultSecret(context.Background(), base64EncodedEncryptedSecret)
		if err != nil {
			slog.Error("Failed to save encrypted generated JWT secret to DB", slog.Any("error", err))
			os.Exit(1)
		}
		return []byte(secret)
	}
	if token.Secret == "" {
		slog.Error("Either JWT_MASTER_KEY or JWT_SECRET_KEY env variables should be set")
		os.Exit(1)
	}
	base64DecodedSecretKey, err := base64.StdEncoding.DecodeString(token.Secret)
	if err != nil {
		slog.Error("Failed to decode JWT_SECRET_KEY")
		os.Exit(1)
	}
	return base64DecodedSecretKey
}

func generateJWTSecret() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		slog.Error("JWT_TOKEN_SECRET is not set. Failed to generate default JWT secret", slog.Any("error", err))
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
