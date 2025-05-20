package users

import (
	"context"
	"testing"

	"github.com/spdeepak/go-jwt-server/users/repository"
	"github.com/stretchr/testify/assert"
)

func TestStorage_UserSignup(t *testing.T) {
	ctx := context.Background()
	arg := repository.SignupParams{
		Email:     "first.last@trendyol.com",
		FirstName: "First name",
		LastName:  "Last name",
		Password:  "Som€_$trong_P@$$word",
	}

	querier := repository.NewMockQuerier(t)
	querier.On("Signup", ctx, arg).Return(nil)

	storage := NewStorage(querier)

	err := storage.UserSignup(ctx, arg)
	assert.NoError(t, err)
}

func TestStorage_GetUser(t *testing.T) {
	ctx := context.Background()
	email := "first.last@trendyol.com"

	querier := repository.NewMockQuerier(t)
	querier.On("UserLogin", ctx, email).
		Return(repository.User{
			Email:     "first.last@trendyol.com",
			FirstName: "First name",
			LastName:  "Last name",
			Password:  "Som€_$trong_P@$$word"},
			nil)

	storage := NewStorage(querier)

	user, err := storage.GetUser(ctx, email)
	assert.NoError(t, err)
	assert.NotNil(t, user)
}
