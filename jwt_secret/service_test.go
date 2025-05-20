package jwt_secret

import (
	"context"
	"testing"

	"github.com/spdeepak/go-jwt-server/jwt_secret/repository"
	"github.com/stretchr/testify/assert"
)

func Test_service_GenerateTokenPair(t *testing.T) {
	ctx := context.Background()
	secret := "JWT_$€CR€T"
	querier := repository.NewMockQuerier(t)
	querier.On("GetDefaultSecret", ctx).Return(repository.JwtSecret{Secret: secret}, nil)
	storage := NewStorage(querier)
	service := NewService(storage)

	user := repository.User{
		Email:     "first.last@example.com",
		FirstName: "First",
		LastName:  "Last",
	}
	response, err := service.GenerateTokenPair(user)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
}

func Test_service_VerifyRefreshToken_OK(t *testing.T) {
	ctx := context.Background()
	secret := "JWT_$€CR€T"
	querier := repository.NewMockQuerier(t)
	querier.On("GetDefaultSecret", ctx).Return(repository.JwtSecret{Secret: secret}, nil)
	storage := NewStorage(querier)
	service := NewService(storage)

	user := repository.User{
		Email:     "first.last@example.com",
		FirstName: "First",
		LastName:  "Last",
	}
	response, err := service.GenerateTokenPair(user)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
	tokens, claims, err := service.VerifyRefreshToken(response.RefreshToken)
	assert.NoError(t, err)
	assert.NotNil(t, tokens)
	assert.NotNil(t, claims)
}
