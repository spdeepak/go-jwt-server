package twoFA

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/tokens"
	tokenRepo "github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/spdeepak/go-jwt-server/twoFA/repository"
	"github.com/spdeepak/go-jwt-server/users"
	userRepo "github.com/spdeepak/go-jwt-server/users/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestService_GenerateSecret_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.NewString()
	email := "first.last@example.com"
	query := repository.NewMockQuerier(t)
	query.On("Setup2FA", ctx, mock.MatchedBy(func(c repository.Setup2FAParams) bool {
		return c.UserID == uuid.MustParse(userId) && c.Secret != "" && c.Url != ""
	})).Return(nil)
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage, nil, nil)

	response, err := otpService.Setup2FA(ctx, email, userId)
	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	assert.NotEmpty(t, response.Secret)
	assert.NotEmpty(t, response.QrImage)
}

func TestService_GenerateSecret_NOK_SaveToDBError(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.NewString()
	email := "first.last@example.com"
	query := repository.NewMockQuerier(t)
	query.On("Setup2FA", ctx, mock.MatchedBy(func(c repository.Setup2FAParams) bool {
		return c.UserID == uuid.MustParse(userId) && c.Secret != "" && c.Url != ""
	})).Return(errors.New("error"))
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage, nil, nil)

	response, err := otpService.Setup2FA(ctx, email, userId)
	assert.Error(t, err)
	assert.Empty(t, response)
}

func TestService_Verify2FALogin_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	userId := uuid.NewString()
	//User
	userQuery := userRepo.NewMockQuerier(t)
	userStorage := users.NewStorage(userQuery)
	userService := users.NewService(userStorage, nil)
	user := userRepo.User{
		ID:        uuid.MustParse(userId),
		Email:     "first.last@example.com",
		FirstName: "First",
		LastName:  "Last",
	}
	userQuery.On("GetUserById", ctx, uuid.MustParse(userId)).Return(user, nil)
	//Token
	tokenQuery := tokenRepo.NewMockQuerier(t)
	tokenStorage := tokens.NewStorage(tokenQuery)
	tokenService := tokens.NewService(tokenStorage, []byte("JWT_$€CR€T"))
	tokenQuery.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	//2FA
	twoFAQuery := repository.NewMockQuerier(t)
	twoFAQuery.On("Get2FADetails", ctx, uuid.MustParse(userId)).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	optStorage := NewStorage(twoFAQuery)
	otpService := NewService("go-jwt-server", optStorage, userService, tokenService)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)
	valid, err := otpService.Verify2FALogin(ctx, api.Verify2FAParams{XLoginSource: "test", UserAgent: "test"}, userId, passcode)
	assert.NoError(t, err)
	assert.NotNil(t, valid)
	assert.NotEmpty(t, valid)
}

func TestService_Verify2FALogin_NOK_MinuteOldPasscode(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.NewString()
	query := repository.NewMockQuerier(t)
	query.On("Get2FADetails", ctx, uuid.MustParse(userId)).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage, nil, nil)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)
	valid, err := otpService.Verify2FALogin(ctx, api.Verify2FAParams{}, userId, passcode)
	assert.Error(t, err)
	assert.Empty(t, valid)
}

func TestService_Verify2FALogin_NOK_NotFoundInDB(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.NewString()
	query := repository.NewMockQuerier(t)
	query.On("Get2FADetails", ctx, uuid.MustParse(userId)).Return(repository.Users2fa{}, errors.New("error"))
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage, nil, nil)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)
	valid, err := otpService.Verify2FALogin(ctx, api.Verify2FAParams{}, userId, passcode)
	assert.Error(t, err)
	assert.Empty(t, valid)
}

func TestService_Delete2FA_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.NewString()
	query := repository.NewMockQuerier(t)
	query.On("Get2FADetails", ctx, uuid.MustParse(userId)).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	query.On("Delete2FA", ctx, repository.Delete2FAParams{UserID: uuid.MustParse(userId), Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}).Return(nil)
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage, nil, nil)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)
	err = otpService.Delete2FA(ctx, userId, passcode)
	assert.NoError(t, err)
}

func TestService_Delete2FA_NOK_MinuteOldPasscode(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.NewString()
	query := repository.NewMockQuerier(t)
	query.On("Get2FADetails", ctx, uuid.MustParse(userId)).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage, nil, nil)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)
	err = otpService.Delete2FA(ctx, userId, passcode)
	assert.Error(t, err)
}

func TestService_Delete2FA_NOK_NotFoundInDB(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.NewString()
	query := repository.NewMockQuerier(t)
	query.On("Get2FADetails", ctx, uuid.MustParse(userId)).Return(repository.Users2fa{}, errors.New("error"))
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage, nil, nil)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)
	err = otpService.Delete2FA(ctx, userId, passcode)
	assert.Error(t, err)
}

func TestService_Delete2FA_NOK_DeleteInDB(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.NewString()
	query := repository.NewMockQuerier(t)
	query.On("Get2FADetails", ctx, uuid.MustParse(userId)).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	query.On("Delete2FA", ctx, repository.Delete2FAParams{UserID: uuid.MustParse(userId), Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}).Return(errors.New("error"))
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage, nil, nil)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)
	err = otpService.Delete2FA(ctx, userId, passcode)
	assert.Error(t, err)
}
