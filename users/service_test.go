package users

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/tokens"
	token "github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/spdeepak/go-jwt-server/users/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestService_Signup_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
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
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("User-Agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

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
	tokenStorage := tokens.NewMockStorage(t)
	tokenStorage.On("saveToken", ctx, mock.MatchedBy(func(token token.SaveTokenParams) bool {
		return token.Token != "" && token.RefreshToken != "" && token.IpAddress == "192.168.1.100" &&
			token.UserAgent == "test" && token.DeviceName == "" && token.CreatedBy == "api"
	})).Return(nil)
	tokenService := tokens.NewService(tokenStorage, []byte("JWT_$€Cr€t"))
	userService := NewService(userStorage, tokenService)
	loginParams := api.LoginParams{
		XLoginSource: api.LoginParamsXLoginSourceApi,
		UserAgent:    "test",
	}
	res, err := userService.Login(ctx, loginParams, userLogin)
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
}

func TestService_Login_NOK_WrongPassword(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
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
	userService := NewService(userStorage, nil)

	loginParams := api.LoginParams{
		XLoginSource: api.LoginParamsXLoginSourceApi,
		UserAgent:    "test",
	}
	res, err := userService.Login(ctx, loginParams, userLogin)
	assert.Error(t, err)
	assert.NotNil(t, res)
	assert.Empty(t, res.AccessToken)
	assert.Empty(t, res.RefreshToken)
}

func TestService_Login_NOK_DB(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@trendyol.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_$trong_P@$$word",
	}

	querier := repository.NewMockQuerier(t)
	querier.On("UserLogin", ctx, email).Return(repository.User{}, errors.New("sql: no rows in result set"))

	userStorage := NewStorage(querier)
	userService := NewService(userStorage, nil)

	loginParams := api.LoginParams{
		XLoginSource: api.LoginParamsXLoginSourceApi,
		UserAgent:    "test",
	}
	res, err := userService.Login(ctx, loginParams, userLogin)
	assert.Error(t, err)
	assert.NotNil(t, res)
	assert.Empty(t, res.AccessToken)
	assert.Empty(t, res.RefreshToken)
}

func TestService_Login_NOK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@trendyol.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_$trong_P@$$word",
	}

	querier := repository.NewMockQuerier(t)
	querier.On("UserLogin", ctx, email).Return(repository.User{}, errors.New("error"))

	userStorage := NewStorage(querier)
	userService := NewService(userStorage, nil)
	loginParams := api.LoginParams{
		XLoginSource: api.LoginParamsXLoginSourceApi,
		UserAgent:    "test",
	}
	res, err := userService.Login(ctx, loginParams, userLogin)
	assert.Error(t, err)
	assert.NotNil(t, res)
	assert.Empty(t, res.AccessToken)
	assert.Empty(t, res.RefreshToken)
}
