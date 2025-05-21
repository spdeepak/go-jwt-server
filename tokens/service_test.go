package tokens

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestService_GenerateTokenPair(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	storage := NewStorage(query)
	service := NewService(storage, []byte(secret))

	user := repository.User{
		Email:     "first.last@example.com",
		FirstName: "First",
		LastName:  "Last",
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	tokenParams := TokenParams{
		XLoginSource: string(api.LoginSourceApi),
		UserAgent:    "test",
	}
	response, err := service.GenerateNewTokenPair(ctx, tokenParams, user)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
}

func TestService_ValidateRefreshToken_OK(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	storage := NewStorage(query)
	service := NewService(storage, []byte(secret))

	user := repository.User{
		Email:     "first.last@example.com",
		FirstName: "First",
		LastName:  "Last",
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	tokenParams := TokenParams{
		XLoginSource: string(api.LoginSourceApi),
		UserAgent:    "test",
	}
	response, err := service.GenerateNewTokenPair(ctx, tokenParams, user)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	query.On("IsRefreshValid", ctx, hashToken(response.RefreshToken)).Return(int32(1), nil)

	claims, err := service.ValidateRefreshToken(ctx, response.RefreshToken)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
}

func TestService_ValidateRefreshToken_NOK_AlreadyRevoked(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	storage := NewStorage(query)
	service := NewService(storage, []byte(secret))

	user := repository.User{
		Email:     "first.last@example.com",
		FirstName: "First",
		LastName:  "Last",
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	tokenParams := TokenParams{
		XLoginSource: string(api.LoginSourceApi),
		UserAgent:    "test",
	}
	response, err := service.GenerateNewTokenPair(ctx, tokenParams, user)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	query.On("IsRefreshValid", ctx, hashToken(response.RefreshToken)).Return(int32(0), nil)

	claims, err := service.ValidateRefreshToken(ctx, response.RefreshToken)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestService_ValidateRefreshToken_NOK(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	storage := NewStorage(query)
	service := NewService(storage, []byte(secret))

	user := repository.User{
		Email:     "first.last@example.com",
		FirstName: "First",
		LastName:  "Last",
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	tokenParams := TokenParams{
		XLoginSource: string(api.LoginSourceApi),
		UserAgent:    "test",
	}
	response, err := service.GenerateNewTokenPair(ctx, tokenParams, user)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	claims, err := NewService(storage, []byte(secret+"asd")).ValidateRefreshToken(ctx, response.RefreshToken)
	assert.Error(t, err)
	assert.Equal(t, "token signature is invalid: signature is invalid", err.(httperror.HttpError).Metadata)
	assert.Nil(t, claims)
}

func TestService_RevokeAllTokens_OK(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("RevokeAllTokens", mock.Anything, "first.last@example.com").Return(nil)
	storage := NewStorage(query)
	service := NewService(storage, []byte(secret))

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	err := service.RevokeAllTokens(ctx, "first.last@example.com")
	assert.NoError(t, err)
}

func TestService_RevokeAllTokens_NOK(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("RevokeAllTokens", mock.Anything, "first.last@example.com").Return(errors.New("error"))
	storage := NewStorage(query)
	service := NewService(storage, []byte(secret))

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	err := service.RevokeAllTokens(ctx, "first.last@example.com")
	assert.Error(t, err)
	assert.Equal(t, httperror.TokenRevokeFailed, err.(httperror.HttpError).ErrorCode)
}

func TestService_RevokeRefreshToken_OK(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	storage := NewStorage(query)
	service := NewService(storage, []byte(secret))

	user := repository.User{
		Email:     "first.last@example.com",
		FirstName: "First",
		LastName:  "Last",
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	tokenParams := TokenParams{
		XLoginSource: string(api.LoginSourceApi),
		UserAgent:    "test",
	}
	response, err := service.GenerateNewTokenPair(ctx, tokenParams, user)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	hashedRefreshToken := hashToken(response.RefreshToken)
	query.On("RevokeRefreshToken", ctx, hashedRefreshToken).Return(nil)

	err = service.RevokeRefreshToken(ctx, api.RevokeRefreshTokenParams{}, api.RevokeRefresh{RefreshToken: response.RefreshToken})
	assert.NoError(t, err)
}

func TestService_RevokeRefreshToken_NOK_RefreshTokenInvalid(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	storage := NewStorage(query)
	service := NewService(storage, []byte(secret))

	user := repository.User{
		Email:     "first.last@example.com",
		FirstName: "First",
		LastName:  "Last",
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	tokenParams := TokenParams{
		XLoginSource: string(api.LoginSourceApi),
		UserAgent:    "test",
	}
	response, err := service.GenerateNewTokenPair(ctx, tokenParams, user)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	hashedRefreshToken := hashToken(response.RefreshToken)
	query.On("RevokeRefreshToken", ctx, hashedRefreshToken).Return(errors.New("sql: no rows in result set"))

	err = service.RevokeRefreshToken(ctx, api.RevokeRefreshTokenParams{}, api.RevokeRefresh{RefreshToken: response.RefreshToken})
	assert.Error(t, err)
	assert.Equal(t, httperror.InvalidRefreshToken, err.(httperror.HttpError).ErrorCode)
}

func TestService_RevokeRefreshToken_NOK_UnknownDBError(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	storage := NewStorage(query)
	service := NewService(storage, []byte(secret))

	user := repository.User{
		Email:     "first.last@example.com",
		FirstName: "First",
		LastName:  "Last",
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	tokenParams := TokenParams{
		XLoginSource: string(api.LoginSourceApi),
		UserAgent:    "test",
	}
	response, err := service.GenerateNewTokenPair(ctx, tokenParams, user)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	hashedRefreshToken := hashToken(response.RefreshToken)
	query.On("RevokeRefreshToken", ctx, hashedRefreshToken).Return(errors.New("error"))

	err = service.RevokeRefreshToken(ctx, api.RevokeRefreshTokenParams{}, api.RevokeRefresh{RefreshToken: response.RefreshToken})
	assert.Error(t, err)
}
