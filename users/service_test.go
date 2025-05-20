package users

import (
	"context"
	"errors"
	"testing"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/jwt_secret"
	"github.com/spdeepak/go-jwt-server/users/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestService_Signup_OK(t *testing.T) {
	ctx := context.Background()
	user := api.UserSignup{
		Email:     "first.last@trendyol.com",
		FirstName: "First name",
		LastName:  "Last name",
		Password:  "Som€_$trong_P@$$word",
	}

	querier := repository.NewMockQuerier(t)
	querier.On("Signup", ctx, mock.MatchedBy(func(params repository.SignupParams) bool {
		return user.Email == params.Email && user.FirstName == params.FirstName && user.LastName == params.LastName && validPassword(user.Password, params.Password)
	})).Return(nil)
	userStorage := NewStorage(querier)
	userService := NewService(userStorage, nil)

	err := userService.Signup(ctx, user)
	assert.NoError(t, err)
}

func TestService_Login_OK(t *testing.T) {
	ctx := context.Background()
	email := "first.last@trendyol.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_$trong_P@$$word",
	}

	querier := repository.NewMockQuerier(t)
	querier.On("UserLogin", ctx, email).
		Return(repository.User{
			Email:     "first.last@trendyol.com",
			FirstName: "First name",
			LastName:  "Last name",
			Password:  "$2a$10$3gF.MeoEsl3lwQiWj24gYe/9abUGois8FAwKMQlhr9grLof6Y1Ryu"},
			nil)

	userStorage := NewStorage(querier)
	jwtStorage := jwt_secret.NewMockStorage(t)
	jwtStorage.On("GetOrCreateDefaultSecret", ctx, mock.Anything).Return("JWT_$€cr€t", nil)
	jwtService := jwt_secret.NewService(jwtStorage)
	userService := NewService(userStorage, jwtService)

	res, err := userService.Login(ctx, userLogin)
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
}

func TestService_Login_NOK_WrongPassword(t *testing.T) {
	ctx := context.Background()
	email := "first.last@trendyol.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_P@$$word",
	}

	querier := repository.NewMockQuerier(t)
	querier.On("UserLogin", ctx, email).
		Return(repository.User{
			Email:     "first.last@trendyol.com",
			FirstName: "First name",
			LastName:  "Last name",
			Password:  "$2a$10$3gF.MeoEsl3lwQiWj24gYe/9abUGois8FAwKMQlhr9grLof6Y1Ryu"},
			nil)

	userStorage := NewStorage(querier)
	jwtStorage := jwt_secret.NewMockStorage(t)
	jwtStorage.On("GetOrCreateDefaultSecret", ctx, mock.Anything).Return("JWT_$€cr€t", nil)
	jwtService := jwt_secret.NewService(jwtStorage)
	userService := NewService(userStorage, jwtService)

	res, err := userService.Login(ctx, userLogin)
	assert.Error(t, err)
	assert.NotNil(t, res)
	assert.Empty(t, res.AccessToken)
	assert.Empty(t, res.RefreshToken)
}

func TestService_Login_NOK_DB(t *testing.T) {
	ctx := context.Background()
	email := "first.last@trendyol.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_$trong_P@$$word",
	}

	querier := repository.NewMockQuerier(t)
	querier.On("UserLogin", ctx, email).Return(repository.User{}, errors.New("sql: no rows in result set"))

	userStorage := NewStorage(querier)
	userService := NewService(userStorage, nil)

	res, err := userService.Login(ctx, userLogin)
	assert.Error(t, err)
	assert.NotNil(t, res)
	assert.Empty(t, res.AccessToken)
	assert.Empty(t, res.RefreshToken)
}

func TestService_Login_NOK(t *testing.T) {
	ctx := context.Background()
	email := "first.last@trendyol.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_$trong_P@$$word",
	}

	querier := repository.NewMockQuerier(t)
	querier.On("UserLogin", ctx, email).Return(repository.User{}, errors.New("error"))

	userStorage := NewStorage(querier)
	userService := NewService(userStorage, nil)

	res, err := userService.Login(ctx, userLogin)
	assert.Error(t, err)
	assert.NotNil(t, res)
	assert.Empty(t, res.AccessToken)
	assert.Empty(t, res.RefreshToken)
}
