package jwt_secret

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/spdeepak/go-jwt-server/jwt_secret/repository"
)

func TestStorage_saveDefaultSecret_OK_DefaultSecretExists(t *testing.T) {
	ctx := context.Background()
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("CreateDefaultSecret", ctx, secret).Return(nil)
	storage := NewStorage(query)

	err := storage.saveDefaultSecret(ctx, secret)
	assert.NoError(t, err)
}

func TestStorage_saveDefaultSecret_NOK_DefaultSecretCreateFail(t *testing.T) {
	if os.Getenv("FATAL_TEST") == "1" {
		ctx := context.Background()
		secret := "JWT_$€CR€T"
		query := repository.NewMockQuerier(t)
		query.On("GetDefaultSecret", ctx).Return(repository.JwtSecret{Secret: secret}, errors.New("error"))
		query.On("CreateDefaultSecret", ctx, secret).Return(errors.New("error"))
		storage := NewStorage(query)
		storage.saveDefaultSecret(context.Background(), secret)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestStorage_saveDefaultSecret_NOK_DefaultSecretCreateFail")
	cmd.Env = append(os.Environ(), "FATAL_TEST=1")
	output, err := cmd.CombinedOutput()

	assert.Error(t, err, "expected fatal to exit with error")
	assert.Contains(t, string(output), "JWT_TOKEN_SECRET not provided", "expected fatal log message")
}

func TestStorage_getDefaultEncryptedSecret_OK(t *testing.T) {
	query := repository.NewMockQuerier(t)
	ctx := context.Background()
	jwtSecret := repository.JwtSecret{
		ID:         uuid.New(),
		Secret:     "random_secret",
		SecretType: "default",
		IsValid:    true,
		CreatedAt:  time.Now(),
	}
	query.On("GetDefaultSecret", ctx).Return(jwtSecret, nil)
	storage := NewStorage(query)

	jwt, err := storage.getDefaultEncryptedSecret(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, jwt)
	assert.Equal(t, jwtSecret.Secret, jwt)
}

func TestStorage_getDefaultEncryptedSecret_NOK(t *testing.T) {
	query := repository.NewMockQuerier(t)
	ctx := context.Background()
	err := errors.New("error")
	query.On("GetDefaultSecret", ctx).Return(repository.JwtSecret{}, err)
	storage := NewStorage(query)

	jwt, err := storage.getDefaultEncryptedSecret(ctx)
	assert.Error(t, err)
	assert.Empty(t, jwt)
}
