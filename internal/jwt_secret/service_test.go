package jwt_secret

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/spdeepak/go-jwt-server/config"
	"github.com/spdeepak/go-jwt-server/internal/jwt_secret/repository"
)

func TestService_GetOrCreateSecret_OK_SecretInDB(t *testing.T) {
	query := repository.NewMockQuerier(t)
	jwtSecret := repository.JwtSecret{
		ID:         pgtype.UUID{Bytes: uuid.New(), Valid: true},
		Secret:     "pI103TBwAF5w1MaKGQ7jCNawt4xoxxQdA0REzlFkzTUOOUc8OQ40FzrM",
		SecretType: "default",
		IsValid:    true,
		CreatedAt:  time.Now(),
	}
	query.On("GetDefaultSecret", mock.Anything).Return(jwtSecret, nil)
	jwtStorage := NewStorage(query)
	tokenConfig := config.Token{
		MasterKey: "SldUX01AJFTigqxyX0vigqx5X0kkX+KCrF9i4oKsJFQ=",
	}
	plainSecret := "JWT_$€cR€t"
	plainByteSecret := GetOrCreateSecret(tokenConfig, jwtStorage)
	assert.NotNil(t, plainByteSecret)
	assert.NotEmpty(t, plainByteSecret)
	assert.Equal(t, plainSecret, string(plainByteSecret))
}

func TestService_GetOrCreateSecret_OK_SecretNotInDBMasterKeyPresent(t *testing.T) {
	query := repository.NewMockQuerier(t)
	query.On("GetDefaultSecret", mock.Anything).Return(repository.JwtSecret{}, errors.New("no rows in result set"))
	query.On("CreateDefaultSecret", mock.Anything, mock.MatchedBy(func(base64EncodedEncryptedSecret string) bool {
		key, err := base64.StdEncoding.DecodeString(base64EncodedEncryptedSecret)
		return err == nil && string(key) != ""
	})).Return(nil)
	jwtStorage := NewStorage(query)
	tokenConfig := config.Token{
		MasterKey: "SldUX01AJFTigqxyX0vigqx5X0kkX+KCrF9i4oKsJFQ=", //base 64 of "JWT_M@$T€r_K€y_I$_€_b€$T"
	}
	plainByteSecret := GetOrCreateSecret(tokenConfig, jwtStorage)
	assert.NotNil(t, plainByteSecret)
	assert.NotEmpty(t, plainByteSecret)
}

func TestService_GetOrCreateSecret_NOK_SecretInDB_MasterKeyNotSet(t *testing.T) {
	if os.Getenv("FATAL_TEST") == "1" {
		query := repository.NewMockQuerier(t)
		jwtSecret := repository.JwtSecret{
			ID:         pgtype.UUID{Bytes: uuid.New(), Valid: true},
			Secret:     "pI103TBwAF5w1MaKGQ7jCNawt4xoxxQdA0REzlFkzTUOOUc8OQ40FzrM",
			SecretType: "default",
			IsValid:    true,
			CreatedAt:  time.Now(),
		}
		query.On("GetDefaultSecret", mock.Anything).Return(jwtSecret, nil)
		jwtStorage := NewStorage(query)
		tokenConfig := config.Token{}
		GetOrCreateSecret(tokenConfig, jwtStorage)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestService_GetOrCreateSecret_NOK_SecretInDB_MasterKeyNotSet")
	cmd.Env = append(os.Environ(), "FATAL_TEST=1")
	output, err := cmd.CombinedOutput()
	assert.Error(t, err, "expected fatal to exit with error")
	assert.Contains(t, string(output), "JWT_MASTER_KEY not found to decrypt secret key", "expected fatal log message")
}

func TestService_GetOrCreateSecret_NOK_SecretInDB_MasterKeyTooLong(t *testing.T) {
	if os.Getenv("FATAL_TEST") == "1" {
		query := repository.NewMockQuerier(t)
		jwtSecret := repository.JwtSecret{
			ID:         pgtype.UUID{Bytes: uuid.New(), Valid: true},
			Secret:     "pI103TBwAF5w1MaKGQ7jCNawt4xoxxQdA0REzlFkzTUOOUc8OQ40FzrM",
			SecretType: "default",
			IsValid:    true,
			CreatedAt:  time.Now(),
		}
		query.On("GetDefaultSecret", mock.Anything).Return(jwtSecret, nil)
		jwtStorage := NewStorage(query)
		tokenConfig := config.Token{
			MasterKey: base64.StdEncoding.EncodeToString([]byte("JWT_M@$T€r_K€y_I$_Th€_b€$T")),
		}
		GetOrCreateSecret(tokenConfig, jwtStorage)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestService_GetOrCreateSecret_NOK_SecretInDB_MasterKeyTooLong")
	cmd.Env = append(os.Environ(), "FATAL_TEST=1")
	output, err := cmd.CombinedOutput()
	assert.Error(t, err, "expected fatal to exit with error")
	assert.Contains(t, string(output), "Failed to decrypt JWT secret from DB error=\"crypto/aes: invalid key size 34\"", "expected fatal log message")
}

func TestService_GetOrCreateSecret_OK_SecretSetViaEnv(t *testing.T) {
	tokenConfig := config.Token{
		Secret: "SldUXyTigqxjUuKCrHQ=",
	}
	query := repository.NewMockQuerier(t)
	query.On("GetDefaultSecret", mock.Anything).Return(repository.JwtSecret{}, errors.New("no rows in result set"))
	jwtStorage := NewStorage(query)
	secretBytes := GetOrCreateSecret(tokenConfig, jwtStorage)
	assert.Equal(t, "JWT_$€cR€t", string(secretBytes))
}

func TestService_GetOrCreateSecret_NOK_SecretSetViaEnvCorrupted(t *testing.T) {
	if os.Getenv("FATAL_TEST") == "1" {
		tokenConfig := config.Token{
			Secret: "SldUXyTigqxjUuKCrHQ",
		}
		query := repository.NewMockQuerier(t)
		query.On("GetDefaultSecret", mock.Anything).Return(repository.JwtSecret{}, errors.New("no rows in result set"))
		jwtStorage := NewStorage(query)
		GetOrCreateSecret(tokenConfig, jwtStorage)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestService_GetOrCreateSecret_NOK_SecretSetViaEnvCorrupted")
	cmd.Env = append(os.Environ(), "FATAL_TEST=1")
	output, err := cmd.CombinedOutput()
	assert.Error(t, err, "expected fatal to exit with error")
	assert.Contains(t, string(output), "Failed to decode JWT_SECRET_KEY", "expected fatal log message")
}

func TestService_GetOrCreateSecret_NOK_SecretNotSet(t *testing.T) {
	if os.Getenv("FATAL_TEST") == "1" {
		tokenConfig := config.Token{}
		query := repository.NewMockQuerier(t)
		query.On("GetDefaultSecret", mock.Anything).Return(repository.JwtSecret{}, errors.New("no rows in result set"))
		jwtStorage := NewStorage(query)
		GetOrCreateSecret(tokenConfig, jwtStorage)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestService_GetOrCreateSecret_NOK_SecretNotSet")
	cmd.Env = append(os.Environ(), "FATAL_TEST=1")
	output, err := cmd.CombinedOutput()
	assert.Error(t, err, "expected fatal to exit with error")
	assert.Contains(t, string(output), "Either JWT_MASTER_KEY or JWT_SECRET_KEY env variables should be set", "expected fatal log message")
}

func TestEncryptDecrypt_16byteMasterKey(t *testing.T) {
	base64EncodedMasterKey := base64.StdEncoding.EncodeToString([]byte("JWT_M@$T€r_Key"))
	plainSecret := "JWT_$€cR€t"
	base64EncryptSecret, err := Encrypt(plainSecret, base64EncodedMasterKey)
	assert.NoError(t, err)
	assert.NotNil(t, base64EncryptSecret)
	assert.NotEmpty(t, base64EncryptSecret)

	decryptedSecretByte, err := Decrypt(base64EncryptSecret, base64EncodedMasterKey)
	assert.NoError(t, err)
	assert.NotNil(t, decryptedSecretByte)
	assert.Equal(t, string(decryptedSecretByte), plainSecret)
}

func TestEncryptDecrypt_24byteMasterKey(t *testing.T) {
	base64EncodedMasterKey := base64.StdEncoding.EncodeToString([]byte("JWT_M@$T€r_K€y_I$_b$"))
	plainSecret := "JWT_$€cR€t"
	base64EncryptSecret, err := Encrypt(plainSecret, base64EncodedMasterKey)
	assert.NoError(t, err)
	assert.NotNil(t, base64EncryptSecret)
	assert.NotEmpty(t, base64EncryptSecret)

	decryptedSecretByte, err := Decrypt(base64EncryptSecret, base64EncodedMasterKey)
	assert.NoError(t, err)
	assert.NotNil(t, decryptedSecretByte)
	assert.Equal(t, string(decryptedSecretByte), plainSecret)
}

func TestEncryptDecrypt_32byteMasterKey(t *testing.T) {
	base64EncodedMasterKey := base64.StdEncoding.EncodeToString([]byte("JWT_M@$T€r_K€y_I$_€_b€$T"))
	plainSecret := "JWT_$€cR€t"
	base64EncryptSecret, err := Encrypt(plainSecret, base64EncodedMasterKey)
	assert.NoError(t, err)
	assert.NotNil(t, base64EncryptSecret)
	assert.NotEmpty(t, base64EncryptSecret)

	decryptedSecretByte, err := Decrypt(base64EncryptSecret, base64EncodedMasterKey)
	assert.NoError(t, err)
	assert.NotNil(t, decryptedSecretByte)
	assert.Equal(t, string(decryptedSecretByte), plainSecret)
}
