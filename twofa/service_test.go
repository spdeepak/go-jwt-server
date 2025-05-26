package twofa

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/spdeepak/go-jwt-server/twofa/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestService_GenerateSecret_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	userId := uuid.NewString()
	email := "first.last@example.com"
	query := repository.NewMockQuerier(t)
	query.On("CreateTOTP", ctx, mock.MatchedBy(func(c repository.CreateTOTPParams) bool {
		return c.Email == email && c.Secret != "" && c.Url != ""
	})).Return(nil)
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	response, err := otpService.GenerateSecret(ctx, email, userId)
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
	query.On("CreateTOTP", ctx, mock.MatchedBy(func(c repository.CreateTOTPParams) bool {
		return c.Email == email && c.Secret != "" && c.Url != ""
	})).Return(errors.New("error"))
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	response, err := otpService.GenerateSecret(ctx, email, userId)
	assert.Error(t, err)
	assert.Empty(t, response)
}

func TestService_ValidateOTP_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	query := repository.NewMockQuerier(t)
	query.On("GetSecret", ctx, email).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)
	valid, err := otpService.ValidateOTP(ctx, email, passcode, uuid.NewString())
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestService_ValidateOTP_NOK_MinuteOldPasscode(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	query := repository.NewMockQuerier(t)
	query.On("GetSecret", ctx, email).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)
	valid, err := otpService.ValidateOTP(ctx, email, passcode, uuid.NewString())
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestService_ValidateOTP_NOK_NotFoundInDB(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	query := repository.NewMockQuerier(t)
	query.On("GetSecret", ctx, email).Return(repository.Users2fa{}, errors.New("error"))
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)
	valid, err := otpService.ValidateOTP(ctx, email, passcode, uuid.NewString())
	assert.Error(t, err)
	assert.False(t, valid)
}

func TestService_Delete2FA_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	query := repository.NewMockQuerier(t)
	query.On("GetSecret", ctx, email).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	query.On("DeleteSecret", ctx, repository.DeleteSecretParams{Email: email, Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}).Return(nil)
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)
	err = otpService.Delete2FA(ctx, email, passcode, uuid.NewString())
	assert.NoError(t, err)
}

func TestService_Delete2FA_NOK_MinuteOldPasscode(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	query := repository.NewMockQuerier(t)
	query.On("GetSecret", ctx, email).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)
	err = otpService.Delete2FA(ctx, email, passcode, uuid.NewString())
	assert.Error(t, err)
}

func TestService_Delete2FA_NOK_NotFoundInDB(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	query := repository.NewMockQuerier(t)
	query.On("GetSecret", ctx, email).Return(repository.Users2fa{}, errors.New("error"))
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)
	err = otpService.Delete2FA(ctx, email, passcode, uuid.NewString())
	assert.Error(t, err)
}

func TestService_Delete2FA_NOK_DeleteInDB(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	query := repository.NewMockQuerier(t)
	query.On("GetSecret", ctx, email).Return(repository.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	query.On("DeleteSecret", ctx, repository.DeleteSecretParams{Email: email, Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}).Return(errors.New("error"))
	optStorage := NewStorage(query)
	otpService := NewService("go-jwt-server", optStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)
	err = otpService.Delete2FA(ctx, email, passcode, uuid.NewString())
	assert.Error(t, err)
}
