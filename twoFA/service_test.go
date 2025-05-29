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
	"github.com/spdeepak/go-jwt-server/twoFA/repository"
	"github.com/stretchr/testify/assert"
)

func TestService_GenerateSecret_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	otpService := NewService("go-jwt-server", nil)

	response, err := otpService.Setup2FA(ctx, email)
	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	assert.NotEmpty(t, response.Secret)
	assert.NotEmpty(t, response.QrImage)
	assert.Equal(t, "otpauth://totp/go-jwt-server:first.last@example.com?algorithm=SHA1&digits=6&issuer=go-jwt-server&period=30&secret="+response.Secret, response.Url)
}

func TestService_Verify2FALogin_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	userId := uuid.New()
	//2FA
	twoFAQuery := repository.NewMockQuerier(t)
	twoFAQuery.On("Get2FADetails", ctx, userId).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	twoFAStorage := NewStorage(twoFAQuery)
	otpService := NewService("go-jwt-server", twoFAStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)
	valid, err := otpService.Verify2FALogin(ctx, api.Login2FAParams{XLoginSource: "test", UserAgent: "test"}, userId, passcode)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestService_Verify2FALogin_NOK_MinuteOldPasscode(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.New()
	query := repository.NewMockQuerier(t)
	query.On("Get2FADetails", ctx, userId).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)
	valid, err := otpService.Verify2FALogin(ctx, api.Login2FAParams{}, userId, passcode)
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestService_Verify2FALogin_NOK_NotFoundInDB(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.New()
	query := repository.NewMockQuerier(t)
	query.On("Get2FADetails", ctx, userId).Return(repository.Users2fa{}, errors.New("error"))
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)
	valid, err := otpService.Verify2FALogin(ctx, api.Login2FAParams{}, userId, passcode)
	assert.Error(t, err)
	assert.False(t, valid)
}

func TestService_Remove2FA_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.New()
	query := repository.NewMockQuerier(t)
	query.On("Get2FADetails", ctx, userId).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	query.On("Delete2FA", ctx, repository.Delete2FAParams{UserID: userId, Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}).Return(nil)
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)
	err = otpService.Remove2FA(ctx, userId, passcode)
	assert.NoError(t, err)
}

func TestService_Remove2FA_NOK_MinuteOldPasscode(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.New()
	query := repository.NewMockQuerier(t)
	query.On("Get2FADetails", ctx, userId).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)
	err = otpService.Remove2FA(ctx, userId, passcode)
	assert.Error(t, err)
}

func TestService_Remove2FA_NOK_NotFoundInDB(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.New()
	query := repository.NewMockQuerier(t)
	query.On("Get2FADetails", ctx, userId).Return(repository.Users2fa{}, errors.New("error"))
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)
	err = otpService.Remove2FA(ctx, userId, passcode)
	assert.Error(t, err)
}

func TestService_Remove2FA_NOK_DeleteInDB(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.New()
	query := repository.NewMockQuerier(t)
	query.On("Get2FADetails", ctx, userId).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	query.On("Delete2FA", ctx, repository.Delete2FAParams{UserID: userId, Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}).Return(errors.New("error"))
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)
	err = otpService.Remove2FA(ctx, userId, passcode)
	assert.Error(t, err)
}
