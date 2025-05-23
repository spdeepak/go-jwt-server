package jwt_secret

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/spdeepak/go-jwt-server/jwt_secret/repository"
	"github.com/stretchr/testify/assert"
)

func TestStorage_GetOrCreateDefaultSecret_OK_DefaultSecretExists(t *testing.T) {
	ctx := context.Background()
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("GetDefaultSecret", ctx).Return(repository.JwtSecret{Secret: secret}, nil)
	storage := NewStorage(query)

	err := storage.saveDefaultSecret(ctx, secret)
	assert.NoError(t, err)
}

func TestStorage_GetOrCreateDefaultSecret_OK_DefaultSecretNotExist(t *testing.T) {
	ctx := context.Background()
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("GetDefaultSecret", ctx).Return(repository.JwtSecret{Secret: secret}, errors.New("error"))
	query.On("CreateDefaultSecret", ctx, secret).Return(nil)
	storage := NewStorage(query)

	err := storage.saveDefaultSecret(ctx, secret)
	assert.NoError(t, err)
}

func TestStorage_GetOrCreateDefaultSecret_NOK_DefaultSecretCreateFail(t *testing.T) {
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

	cmd := exec.Command(os.Args[0], "-test.run=TestStorage_GetOrCreateDefaultSecret_NOK_DefaultSecretCreateFail")
	cmd.Env = append(os.Environ(), "FATAL_TEST=1")
	output, err := cmd.CombinedOutput()

	assert.Error(t, err, "expected fatal to exit with error")
	assert.Contains(t, string(output), "JWT_TOKEN_SECRET not provided", "expected fatal log message")
}
