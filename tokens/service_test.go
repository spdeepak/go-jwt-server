package tokens

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/stretchr/testify/assert"
)

func Test_service_GenerateTokenPair(t *testing.T) {
	secret := "JWT_$€CR€T"
	querier := repository.NewMockQuerier(t)
	storage := NewStorage(querier)
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
	req.Header.Set("X-Forwarded-For", "192.168.1.100") // or X-Real-IP
	ctx.Request = req

	response, err := service.GenerateTokenPair(ctx, user)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
}

func Test_service_VerifyRefreshToken_OK(t *testing.T) {
	secret := "JWT_$€CR€T"
	querier := repository.NewMockQuerier(t)
	storage := NewStorage(querier)
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

	response, err := service.GenerateTokenPair(ctx, user)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	tokens, claims, err := service.VerifyRefreshToken(ctx, response.RefreshToken)
	assert.NoError(t, err)
	assert.NotNil(t, tokens)
	assert.NotNil(t, claims)
}
