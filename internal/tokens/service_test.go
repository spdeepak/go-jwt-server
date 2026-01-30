package tokens

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/internal/error"
	"github.com/spdeepak/go-jwt-server/internal/tokens/repository"
)

func TestService_GenerateTokenPair(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	tokenService := NewService(query, []byte(secret), "")

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
	response, err := tokenService.GenerateNewTokenPair(ctx, "", tokenParams, user, nil, nil)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
}

func TestService_ValidateRefreshToken_OK(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	tokenService := NewService(query, []byte(secret), "")

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
	response, err := tokenService.GenerateNewTokenPair(ctx, "192.168.1.100", tokenParams, user, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	refreshValidParams := repository.IsRefreshValidParams{
		RefreshToken: hash(response.RefreshToken),
		IpAddress:    "192.168.1.100",
		UserAgent:    "test",
		DeviceName:   "",
	}
	query.On("IsRefreshValid", ctx, refreshValidParams).Return(int32(1), nil)

	claims, err := tokenService.ValidateRefreshToken(ctx, "192.168.1.100", api.RefreshParams{XLoginSource: "api", UserAgent: "test"}, response.RefreshToken)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
}

func TestService_ValidateRefreshToken_NOK_AlreadyRevoked(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	tokenService := NewService(query, []byte(secret), "")

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
	response, err := tokenService.GenerateNewTokenPair(ctx, "192.168.1.100", tokenParams, user, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	refreshValidParams := repository.IsRefreshValidParams{
		RefreshToken: hash(response.RefreshToken),
		IpAddress:    "192.168.1.100",
		UserAgent:    "test",
		DeviceName:   "",
	}

	query.On("IsRefreshValid", ctx, refreshValidParams).Return(int32(0), nil)

	claims, err := tokenService.ValidateRefreshToken(ctx, "192.168.1.100", api.RefreshParams{XLoginSource: "api", UserAgent: "test"}, response.RefreshToken)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestService_ValidateRefreshToken_NOK(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	tokenService := NewService(query, []byte(secret), "")

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
	response, err := tokenService.GenerateNewTokenPair(ctx, "", tokenParams, user, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	claims, err := NewService(query, []byte(secret+"asd"), "").ValidateRefreshToken(ctx, "", api.RefreshParams{XLoginSource: "api", UserAgent: "test"}, response.RefreshToken)
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, "token signature is invalid: signature is invalid", he.Metadata)
	assert.Nil(t, claims)
}

func TestService_RevokeAllTokens_OK(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("RevokeAllTokens", mock.Anything, "first.last@example.com").Return(nil)
	service := NewService(query, []byte(secret), "")

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	err := service.RevokeAllTokens(ctx, "first.last@example.com")
	assert.NoError(t, err)
}

func TestService_RevokeAllTokens_NOK(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("RevokeAllTokens", mock.Anything, "first.last@example.com").Return(errors.New("error"))
	tokenService := NewService(query, []byte(secret), "")

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	err := tokenService.RevokeAllTokens(ctx, "first.last@example.com")
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.TokenRevokeFailed, he.ErrorCode)
}

func TestService_RevokeRefreshToken_OK(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	tokenService := NewService(query, []byte(secret), "")

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
	response, err := tokenService.GenerateNewTokenPair(ctx, "", tokenParams, user, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	hashedRefreshToken := hash(response.RefreshToken)
	query.On("RevokeRefreshToken", ctx, hashedRefreshToken).Return(nil)

	err = tokenService.RevokeRefreshToken(ctx, api.RevokeRefreshTokenParams{}, api.RevokeCurrentSession{RefreshToken: response.RefreshToken})
	assert.NoError(t, err)
}

func TestService_RevokeRefreshToken_NOK_RefreshTokenInvalid(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	tokenService := NewService(query, []byte(secret), "")

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
	response, err := tokenService.GenerateNewTokenPair(ctx, "", tokenParams, user, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	hashedRefreshToken := hash(response.RefreshToken)
	query.On("RevokeRefreshToken", ctx, hashedRefreshToken).Return(errors.New("sql: no rows in result set"))

	err = tokenService.RevokeRefreshToken(ctx, api.RevokeRefreshTokenParams{}, api.RevokeCurrentSession{RefreshToken: response.RefreshToken})
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.InvalidRefreshToken, he.ErrorCode)
}

func TestService_RevokeRefreshToken_NOK_UnknownDBError(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	tokenService := NewService(query, []byte(secret), "")

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
	response, err := tokenService.GenerateNewTokenPair(ctx, "", tokenParams, user, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	hashedRefreshToken := hash(response.RefreshToken)
	query.On("RevokeRefreshToken", ctx, hashedRefreshToken).Return(errors.New("error"))

	err = tokenService.RevokeRefreshToken(ctx, api.RevokeRefreshTokenParams{}, api.RevokeCurrentSession{RefreshToken: response.RefreshToken})
	assert.Error(t, err)
}

func TestService_RefreshAndInvalidateToken_OK(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	tokenService := NewService(query, []byte(secret), "")

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
	response, err := tokenService.GenerateNewTokenPair(ctx, "192.168.1.100", tokenParams, user, []string{}, []string{})
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	hashedRefreshToken := hash(response.RefreshToken)
	var newBearerToken string
	var newRefreshToken string
	query.On("RefreshAndInvalidateToken", ctx, mock.MatchedBy(func(params repository.RefreshAndInvalidateTokenParams) bool {
		newBearerToken = params.NewToken
		newRefreshToken = params.NewRefreshToken
		return len(params.NewToken) > 0 &&
			len(params.NewRefreshToken) > 0 &&
			time.Now().Before(params.TokenExpiresAt) &&
			time.Now().Before(params.RefreshExpiresAt) &&
			len(params.IpAddress) > 1 &&
			params.UserAgent == "Api Testing" &&
			params.DeviceName == "" &&
			params.Email == "first.last@example.com" &&
			params.CreatedBy == "test" &&
			params.OldRefreshToken == hashedRefreshToken
	})).Return(nil)

	tokenResponse, err := tokenService.RefreshAndInvalidateToken(ctx, "192.168.1.100", TokenParams{XLoginSource: "test", UserAgent: "Api Testing"}, api.Refresh{RefreshToken: response.RefreshToken}, repository.User{Email: "first.last@example.com"}, []string{}, []string{})
	assert.NoError(t, err)
	assert.NotNil(t, tokenResponse)
	assert.NotEmpty(t, newBearerToken)
	assert.NotEmpty(t, newRefreshToken)
}

func TestService_RefreshAndInvalidateToken_NOK_InvalidationFailed(t *testing.T) {
	secret := "JWT_$€CR€T"
	query := repository.NewMockQuerier(t)
	query.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	tokenService := NewService(query, []byte(secret), "")

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
	response, err := tokenService.GenerateNewTokenPair(ctx, "192.168.1.100", tokenParams, user, []string{}, []string{})
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)

	hashedRefreshToken := hash(response.RefreshToken)
	var newBearerToken string
	var newRefreshToken string
	query.On("RefreshAndInvalidateToken", ctx, mock.MatchedBy(func(params repository.RefreshAndInvalidateTokenParams) bool {
		newBearerToken = params.NewToken
		newRefreshToken = params.NewRefreshToken
		return len(params.NewToken) > 0 &&
			len(params.NewRefreshToken) > 0 &&
			time.Now().Before(params.TokenExpiresAt) &&
			time.Now().Before(params.RefreshExpiresAt) &&
			len(params.IpAddress) > 1 &&
			params.UserAgent == "Api Testing" &&
			params.DeviceName == "" &&
			params.Email == "first.last@example.com" &&
			params.CreatedBy == "test" &&
			params.OldRefreshToken == hashedRefreshToken
	})).Return(errors.New("test error"))

	tokenResponse, err := tokenService.RefreshAndInvalidateToken(ctx, "192.168.1.100", TokenParams{XLoginSource: "test", UserAgent: "Api Testing"}, api.Refresh{RefreshToken: response.RefreshToken}, repository.User{Email: "first.last@example.com"}, []string{}, []string{})
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.TokenCreationFailed, he.ErrorCode)
	assert.NotNil(t, tokenResponse)
	assert.NotEmpty(t, newBearerToken)
	assert.NotEmpty(t, newRefreshToken)
}

func TestService_ListActiveSessions_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	query := repository.NewMockQuerier(t)
	queryResponse := []repository.Token{
		{
			CreatedBy:        "api-test",
			IpAddress:        "192.168.1.100",
			IssuedAt:         time.Now().Add(-1 * time.Hour),
			RefreshExpiresAt: time.Now().Add(6 * 24 * time.Hour),
			UserAgent:        "user-agent",
		},
	}
	query.On("ListAllActiveSessions", ctx, "first.last@example.com").Return(queryResponse, nil)
	secret := "SOME_RANDOM_SECRET"
	tokenService := NewService(query, []byte(secret), "")

	response, err := tokenService.ListActiveSessions(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	assert.Len(t, response, 1)
	assert.Equal(t, queryResponse[0].CreatedBy, response[0].CreatedBy)
	assert.Equal(t, queryResponse[0].IpAddress, response[0].IpAddress)
	assert.Equal(t, queryResponse[0].IssuedAt, response[0].IssuedAt)
	assert.Equal(t, queryResponse[0].RefreshExpiresAt, response[0].ExpiresAt)
	assert.Equal(t, queryResponse[0].UserAgent, response[0].UserAgent)
}

func TestService_ListActiveSessions_NOK_DBQueryFail(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	query := repository.NewMockQuerier(t)
	query.On("ListAllActiveSessions", ctx, "first.last@example.com").Return(nil, errors.New("errror"))
	secret := "SOME_RANDOM_SECRET"
	tokenService := NewService(query, []byte(secret), "")

	response, err := tokenService.ListActiveSessions(ctx, "first.last@example.com")
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.ActiveSessionsListFailed, he.ErrorCode)
	assert.Nil(t, response)
}

func TestService_GenerateTempToken_OK(t *testing.T) {
	secret := "JWT_$€CR€T"
	tokenService := NewService(nil, []byte(secret), "")
	userId := uuid.New()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	response, err := tokenService.GenerateTempToken(ctx, userId)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.TempToken)
	assert.NotEmpty(t, response.Type)
}
