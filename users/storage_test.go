package users

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/spdeepak/go-jwt-server/users/repository"
)

func TestStorage_UserSignup(t *testing.T) {
	ctx := context.Background()
	arg := repository.SignupParams{
		Email:     "first.last@example.com",
		FirstName: "First name",
		LastName:  "Last name",
		Password:  "Som€_$trong_P@$$word",
	}

	query := repository.NewMockQuerier(t)
	query.On("Signup", ctx, arg).Return(nil)

	storage := NewStorage(query)

	err := storage.UserSignup(ctx, arg)
	assert.NoError(t, err)
}

func TestStorage_GetUser(t *testing.T) {
	ctx := context.Background()
	email := "first.last@example.com"

	query := repository.NewMockQuerier(t)
	query.On("GetEntireUserByEmail", ctx, email).
		Return(repository.GetEntireUserByEmailRow{
			Email:     "first.last@example.com",
			FirstName: "First name",
			LastName:  "Last name",
			Password:  "Som€_$trong_P@$$word"},
			nil)

	storage := NewStorage(query)

	user, err := storage.GetUserByEmail(ctx, email)
	assert.NoError(t, err)
	assert.NotNil(t, user)
}
