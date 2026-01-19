package users

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/internal/error"
	"github.com/spdeepak/go-jwt-server/internal/tokens"
	tokenRepo "github.com/spdeepak/go-jwt-server/internal/tokens/repository"
	"github.com/spdeepak/go-jwt-server/internal/twoFA"
	twoFARepo "github.com/spdeepak/go-jwt-server/internal/twoFA/repository"
	userRepo "github.com/spdeepak/go-jwt-server/internal/users/repository"
)

func TestService_Signup_No2FA_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:     "first.last@example.com",
		FirstName: "First name",
		LastName:  "Last name",
		Password:  "Som€_$trong_P@$$word",
	}

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("Signup", ctx, mock.MatchedBy(func(params userRepo.SignupParams) bool {
		return string(user.Email) == params.Email && user.FirstName == params.FirstName && user.LastName == params.LastName && validPassword(user.Password, params.Password)
	})).Return(nil)
	userService := NewService(userQuery, nil, nil)

	res, err := userService.Signup(ctx, user)
	assert.NoError(t, err)
	assert.Empty(t, res)
}

func TestService_Signup_No2FA_NOK_UserAlreadyExists(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:     "first.last@example.com",
		FirstName: "First name",
		LastName:  "Last name",
		Password:  "Som€_$trong_P@$$word",
	}

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("Signup", ctx, mock.MatchedBy(func(params userRepo.SignupParams) bool {
		return string(user.Email) == params.Email && user.FirstName == params.FirstName && user.LastName == params.LastName && validPassword(user.Password, params.Password)
	})).Return(errors.New("ERROR: duplicate key value violates unique constraint \"users_email_key\" (SQLSTATE 23505)"))

	userService := NewService(userQuery, nil, nil)

	res, err := userService.Signup(ctx, user)
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.UserAlreadyExists, he.ErrorCode)
	assert.Empty(t, res)
}

func TestService_Signup_No2FA_NOK_DBError(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:     "first.last@example.com",
		FirstName: "First name",
		LastName:  "Last name",
		Password:  "Som€_$trong_P@$$word",
	}

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("Signup", ctx, mock.MatchedBy(func(params userRepo.SignupParams) bool {
		return string(user.Email) == params.Email && user.FirstName == params.FirstName && user.LastName == params.LastName && validPassword(user.Password, params.Password)
	})).Return(errors.New("error"))
	userService := NewService(userQuery, nil, nil)

	res, err := userService.Signup(ctx, user)
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.UserSignUpFailed, he.ErrorCode)
	assert.Empty(t, res)
}

func TestService_Signup_2FA_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First name",
		LastName:     "Last name",
		Password:     "Som€_$trong_P@$$word",
		TwoFAEnabled: true,
	}

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("SignupWith2FA", ctx, mock.MatchedBy(func(params userRepo.SignupWith2FAParams) bool {
		return string(user.Email) == params.Email &&
			user.FirstName == params.FirstName &&
			user.LastName == params.LastName &&
			validPassword(user.Password, params.Password) &&
			params.Secret != "" && params.Url != "" &&
			params.Url == "otpauth://totp/go-jwt-server:first.last@example.com?algorithm=SHA1&digits=6&issuer=go-jwt-server&period=30&secret="+params.Secret
	})).Return(nil)
	twoFaService := twoFA.NewService("go-jwt-server", nil)
	userService := NewService(userQuery, twoFaService, nil)

	res, err := userService.Signup(ctx, user)
	assert.NoError(t, err)
	assert.NotEmpty(t, res)
	assert.NotEmpty(t, res.Secret)
	assert.NotEmpty(t, res.QrImage)
}

func TestService_Signup_2FA_NOK_UserAlreadyExists(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First name",
		LastName:     "Last name",
		Password:     "Som€_$trong_P@$$word",
		TwoFAEnabled: true,
	}

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("SignupWith2FA", ctx, mock.MatchedBy(func(params userRepo.SignupWith2FAParams) bool {
		return string(user.Email) == params.Email &&
			user.FirstName == params.FirstName &&
			user.LastName == params.LastName &&
			validPassword(user.Password, params.Password) &&
			params.Secret != "" && params.Url != "" &&
			params.Url == "otpauth://totp/go-jwt-server:first.last@example.com?algorithm=SHA1&digits=6&issuer=go-jwt-server&period=30&secret="+params.Secret
	})).Return(errors.New("ERROR: duplicate key value violates unique constraint \"users_email_key\" (SQLSTATE 23505)"))
	twoFaService := twoFA.NewService("go-jwt-server", nil)
	userService := NewService(userQuery, twoFaService, nil)

	res, err := userService.Signup(ctx, user)
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.UserAlreadyExists, he.ErrorCode)
	assert.Empty(t, res)
}

func TestService_Signup_2FA_NOK_DBError(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First name",
		LastName:     "Last name",
		Password:     "Som€_$trong_P@$$word",
		TwoFAEnabled: true,
	}

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("SignupWith2FA", ctx, mock.MatchedBy(func(params userRepo.SignupWith2FAParams) bool {
		return string(user.Email) == params.Email &&
			user.FirstName == params.FirstName &&
			user.LastName == params.LastName &&
			validPassword(user.Password, params.Password) &&
			params.Secret != "" && params.Url != "" &&
			params.Url == "otpauth://totp/go-jwt-server:first.last@example.com?algorithm=SHA1&digits=6&issuer=go-jwt-server&period=30&secret="+params.Secret
	})).Return(errors.New("ERROR"))
	twoFaService := twoFA.NewService("go-jwt-server", nil)
	userService := NewService(userQuery, twoFaService, nil)

	res, err := userService.Signup(ctx, user)
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.UserSignUpWith2FAFailed, he.ErrorCode)
	assert.Empty(t, res)
}

func TestService_Login_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("User-Agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	email := "first.last@example.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_$trong_P@$$word",
	}

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("GetEntireUserByEmail", ctx, email).
		Return(userRepo.GetEntireUserByEmailRow{
			Email:     "first.last@example.com",
			FirstName: "First name",
			LastName:  "Last name",
			Password:  "$2a$10$3gF.MeoEsl3lwQiWj24gYe/9abUGois8FAwKMQlhr9grLof6Y1Ryu"},
			nil)

	tokenQuery := tokenRepo.NewMockQuerier(t)
	tokenStorage := tokens.NewStorage(tokenQuery)
	tokenQuery.On("SaveToken", ctx, mock.MatchedBy(func(token tokenRepo.SaveTokenParams) bool {
		return token.Token != "" && token.RefreshToken != "" && token.IpAddress == "192.168.1.100" &&
			token.UserAgent == "test" && token.DeviceName == "" && token.CreatedBy == "api"
	})).Return(nil)
	tokenService := tokens.NewService(nil, []byte("JWT_$€Cr€t"), "")
	userService := NewService(userQuery, nil, tokenService)
	loginParams := api.LoginParams{
		XLoginSource: api.LoginParamsXLoginSourceApi,
		UserAgent:    "test",
	}
	res, err := userService.Login(ctx, loginParams, userLogin)
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.NotEmpty(t, res.(api.LoginSuccessWithJWT).AccessToken)
	assert.NotEmpty(t, res.(api.LoginSuccessWithJWT).RefreshToken)
}

func TestService_Login_NOK_WrongPassword(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_P@$$word",
	}

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("GetEntireUserByEmail", ctx, email).
		Return(userRepo.GetEntireUserByEmailRow{
			Email:     "first.last@example.com",
			FirstName: "First name",
			LastName:  "Last name",
			Password:  "$2a$10$3gF.MeoEsl3lwQiWj24gYe/9abUGois8FAwKMQlhr9grLof6Y1Ryu"},
			nil)

	userService := NewService(userQuery, nil, nil)

	loginParams := api.LoginParams{
		XLoginSource: api.LoginParamsXLoginSourceApi,
		UserAgent:    "test",
	}
	res, err := userService.Login(ctx, loginParams, userLogin)
	assert.Error(t, err)
	assert.NotNil(t, res)
	assert.Empty(t, res.(api.LoginSuccessWithJWT).AccessToken)
	assert.Empty(t, res.(api.LoginSuccessWithJWT).RefreshToken)
}

func TestService_Login_NOK_DB(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_$trong_P@$$word",
	}

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("GetEntireUserByEmail", ctx, email).Return(userRepo.GetEntireUserByEmailRow{}, errors.New("sql: no rows in result set"))

	userService := NewService(userQuery, nil, nil)

	loginParams := api.LoginParams{
		XLoginSource: api.LoginParamsXLoginSourceApi,
		UserAgent:    "test",
	}
	res, err := userService.Login(ctx, loginParams, userLogin)
	assert.Error(t, err)
	assert.NotNil(t, res)
	assert.Empty(t, res.(api.LoginSuccessWithJWT).AccessToken)
	assert.Empty(t, res.(api.LoginSuccessWithJWT).RefreshToken)
}

func TestService_Login_NOK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_$trong_P@$$word",
	}

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("GetEntireUserByEmail", ctx, email).Return(userRepo.GetEntireUserByEmailRow{}, errors.New("error"))

	userService := NewService(userQuery, nil, nil)
	loginParams := api.LoginParams{
		XLoginSource: api.LoginParamsXLoginSourceApi,
		UserAgent:    "test",
	}
	res, err := userService.Login(ctx, loginParams, userLogin)
	assert.Error(t, err)
	assert.NotNil(t, res)
	assert.Empty(t, res.(api.LoginSuccessWithJWT).AccessToken)
	assert.Empty(t, res.(api.LoginSuccessWithJWT).RefreshToken)
}

func TestService_Login2FA_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	userId := pgtype.UUID{Bytes: uuid.New(), Valid: true}

	//2FA
	twoFAQuery := twoFARepo.NewMockQuerier(t)
	twoFAQuery.On("Get2FADetails", ctx, userId).Return(twoFARepo.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFAService := twoFA.NewService("go-jwt-server", twoFAStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)

	secret := "JWT_$€CR€T"
	tokenQuery := tokenRepo.NewMockQuerier(t)
	tokenQuery.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	tokenStorage := tokens.NewStorage(tokenQuery)
	tokenService := tokens.NewService(nil, []byte(secret), "")

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("GetUserById", ctx, userId).Return(userRepo.User{ID: userId, Email: "first.last@example.com", FirstName: "First", LastName: "Last"}, nil)

	userService := NewService(userQuery, twoFAService, tokenService)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userId.Bytes, passcode)
	assert.NoError(t, err)
	assert.NotEmpty(t, login2FA)
	assert.NotEmpty(t, login2FA.AccessToken)
	assert.NotEmpty(t, login2FA.RefreshToken)
}

func TestService_Login2FA_NOK_UserLocked(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	userId := pgtype.UUID{Bytes: uuid.New(), Valid: true}

	//2FA
	twoFAQuery := twoFARepo.NewMockQuerier(t)
	twoFAQuery.On("Get2FADetails", ctx, userId).Return(twoFARepo.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFAService := twoFA.NewService("go-jwt-server", twoFAStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("GetUserById", ctx, userId).Return(userRepo.User{ID: userId, Email: "first.last@example.com", FirstName: "First", LastName: "Last", Locked: true}, nil)

	userService := NewService(userQuery, twoFAService, nil)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userId.Bytes, passcode)
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.UserAccountLocked, he.ErrorCode)
	assert.Empty(t, login2FA)
}

func TestService_Login2FA_NOK_UserNotExist(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	userId := uuid.New()

	//2FA
	twoFAQuery := twoFARepo.NewMockQuerier(t)
	twoFAQuery.On("Get2FADetails", ctx, mock.MatchedBy(func(id pgtype.UUID) bool {
		return id.Valid
	})).Return(twoFARepo.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFAService := twoFA.NewService("go-jwt-server", twoFAStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("GetUserById", ctx, mock.MatchedBy(func(id pgtype.UUID) bool {
		return id.Valid
	})).Return(userRepo.User{}, errors.New("no rows in result set"))

	userService := NewService(userQuery, twoFAService, nil)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userId, passcode)
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.InvalidCredentials, he.ErrorCode)
	assert.Empty(t, login2FA)
}

func TestService_Login2FA_NOK_UserGetError(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	userId := uuid.New()

	//2FA
	twoFAQuery := twoFARepo.NewMockQuerier(t)
	twoFAQuery.On("Get2FADetails", ctx, mock.MatchedBy(func(id pgtype.UUID) bool {
		return id.Valid
	})).Return(twoFARepo.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFAService := twoFA.NewService("go-jwt-server", twoFAStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)

	userQuery := userRepo.NewMockQuerier(t)
	userQuery.On("GetUserById", ctx, mock.MatchedBy(func(id pgtype.UUID) bool {
		return id.Valid
	})).Return(userRepo.User{}, errors.New("error"))

	userService := NewService(userQuery, twoFAService, nil)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userId, passcode)
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.UndefinedErrorCode, he.ErrorCode)
	assert.Empty(t, login2FA)
}

func TestService_Login2FA_NOK_Old2FACode(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	userId := uuid.New()

	//2FA
	twoFAQuery := twoFARepo.NewMockQuerier(t)
	twoFAQuery.On("Get2FADetails", ctx, mock.MatchedBy(func(id pgtype.UUID) bool {
		return id.Valid
	})).Return(twoFARepo.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFAService := twoFA.NewService("go-jwt-server", twoFAStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)

	userService := NewService(nil, twoFAService, nil)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userId, passcode)
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.InvalidTwoFA, he.ErrorCode)
	assert.Empty(t, login2FA)
}
