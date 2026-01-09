package users

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	repository2 "github.com/spdeepak/go-jwt-server/internal/users/repository"
)

func TestStorage_UserSignup(t *testing.T) {
	ctx := context.Background()
	arg := repository2.SignupParams{
		Email:     "first.last@example.com",
		FirstName: "First name",
		LastName:  "Last name",
		Password:  "Som€_$trong_P@$$word",
	}

	query := repository2.NewMockQuerier(t)
	query.On("Signup", ctx, arg).Return(nil)

	storage := NewStorage(query)

	err := storage.UserSignup(ctx, arg)
	assert.NoError(t, err)
}

func TestStorage_GetUser(t *testing.T) {
	ctx := context.Background()
	email := "first.last@example.com"

	query := repository2.NewMockQuerier(t)
	query.On("GetEntireUserByEmail", ctx, email).
		Return(repository2.GetEntireUserByEmailRow{
			Email:     "first.last@example.com",
			FirstName: "First name",
			LastName:  "Last name",
			Password:  "Som€_$trong_P@$$word"},
			nil)

	storage := NewStorage(query)

	user, err := storage.GetUserByEmailForAuth(ctx, email)
	assert.NoError(t, err)
	assert.NotNil(t, user)
}
