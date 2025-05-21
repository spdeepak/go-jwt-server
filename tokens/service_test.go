package tokens

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func Test_service_GenerateTokenPair(t *testing.T) {
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

func Test_service_VerifyRefreshToken_OK(t *testing.T) {
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

	claims, err := service.VerifyRefreshToken(ctx, response.RefreshToken)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
}

func Test_service_VerifyRefreshToken_NOK_AlreadyRevoked(t *testing.T) {
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

	claims, err := service.VerifyRefreshToken(ctx, response.RefreshToken)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func Test_service_VerifyRefreshToken_NOK(t *testing.T) {
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

	claims, err := NewService(storage, []byte(secret+"asd")).VerifyRefreshToken(ctx, response.RefreshToken)
	assert.Error(t, err)
	assert.Equal(t, "token signature is invalid: signature is invalid", err.(httperror.HttpError).Metadata)
	assert.Nil(t, claims)
}
