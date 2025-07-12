package users

import (
	"errors"
	"log"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/config"
	"github.com/spdeepak/go-jwt-server/db"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/tokens"
	token "github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/spdeepak/go-jwt-server/twoFA"
	twoFARepo "github.com/spdeepak/go-jwt-server/twoFA/repository"
	"github.com/spdeepak/go-jwt-server/users/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var userStorage Storage

func TestMain(m *testing.M) {
	dbConnection, err := db.Connect(config.PostgresConfig{
		Host:     "localhost",
		Port:     "5432",
		DBName:   "jwt_server",
		UserName: "admin",
		Password: "admin",
		SSLMode:  "disable",
		Timeout:  5 * time.Second,
		MaxRetry: 5,
	})
	if err != nil {
		log.Fatalf("failed to connect to DB: %v", err)
	}
	db.RunMigrationQueries(dbConnection, "../migrations")
	query := repository.New(dbConnection.DB)
	userStorage = NewStorage(query)
	// Run all tests
	code := m.Run()

	// Optional: Clean up (e.g., drop DB or close connection)
	_ = dbConnection.DB.Close()
	os.Exit(code)
}

func TestIntegrationService_Signup_No2FA(t *testing.T) {
	t.Run("Create New User", func(t *testing.T) {
		signup_No2fa_OK(t)
	})
	t.Run("Create User already exists", func(t *testing.T) {
		signup_No2FA_NOK_UserAlreadyExists(t)
	})
}

func signup_No2fa_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:     "first.last@example.com",
		FirstName: "First name",
		LastName:  "Last name",
		Password:  "Som€_$trong_P@$$word",
	}
	userService := NewService(userStorage, nil, nil)

	res, err := userService.Signup(ctx, user)
	assert.NoError(t, err)
	assert.Empty(t, res)
}

func signup_No2FA_NOK_UserAlreadyExists(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:     "first.last@example.com",
		FirstName: "First name",
		LastName:  "Last name",
		Password:  "Som€_$trong_P@$$word",
	}

	userService := NewService(userStorage, nil, nil)

	res, err := userService.Signup(ctx, user)
	assert.Error(t, err)
	assert.Equal(t, httperror.UserAlreadyExists, err.(httperror.HttpError).ErrorCode)
	assert.Empty(t, res)
}

func TestIntegrationService_Signup_2FA_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First name",
		LastName:     "Last name",
		Password:     "Som€_$trong_P@$$word",
		TwoFAEnabled: true,
	}

	query := repository.NewMockQuerier(t)
	query.On("SignupWith2FA", ctx, mock.MatchedBy(func(params repository.SignupWith2FAParams) bool {
		return string(user.Email) == params.Email &&
			user.FirstName == params.FirstName &&
			user.LastName == params.LastName &&
			validPassword(user.Password, params.Password) &&
			params.Secret != "" && params.Url != "" &&
			params.Url == "otpauth://totp/go-jwt-server:first.last@example.com?algorithm=SHA1&digits=6&issuer=go-jwt-server&period=30&secret="+params.Secret
	})).Return(nil)
	twoFaService := twoFA.NewService("go-jwt-server", nil)
	userStorage := NewStorage(query)
	userService := NewService(userStorage, twoFaService, nil)

	res, err := userService.Signup(ctx, user)
	assert.NoError(t, err)
	assert.NotEmpty(t, res)
	assert.NotEmpty(t, res.Secret)
	assert.NotEmpty(t, res.QrImage)
}

func TestIntegrationService_Signup_2FA_NOK_UserAlreadyExists(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First name",
		LastName:     "Last name",
		Password:     "Som€_$trong_P@$$word",
		TwoFAEnabled: true,
	}

	query := repository.NewMockQuerier(t)
	query.On("SignupWith2FA", ctx, mock.MatchedBy(func(params repository.SignupWith2FAParams) bool {
		return string(user.Email) == params.Email &&
			user.FirstName == params.FirstName &&
			user.LastName == params.LastName &&
			validPassword(user.Password, params.Password) &&
			params.Secret != "" && params.Url != "" &&
			params.Url == "otpauth://totp/go-jwt-server:first.last@example.com?algorithm=SHA1&digits=6&issuer=go-jwt-server&period=30&secret="+params.Secret
	})).Return(errors.New("ERROR: duplicate key value violates unique constraint \"users_email_key\" (SQLSTATE 23505)"))
	twoFaService := twoFA.NewService("go-jwt-server", nil)
	userStorage := NewStorage(query)
	userService := NewService(userStorage, twoFaService, nil)

	res, err := userService.Signup(ctx, user)
	assert.Error(t, err)
	assert.Equal(t, httperror.UserAlreadyExists, err.(httperror.HttpError).ErrorCode)
	assert.Empty(t, res)
}

func TestIntegrationService_Signup_2FA_NOK_DBError(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First name",
		LastName:     "Last name",
		Password:     "Som€_$trong_P@$$word",
		TwoFAEnabled: true,
	}

	query := repository.NewMockQuerier(t)
	query.On("SignupWith2FA", ctx, mock.MatchedBy(func(params repository.SignupWith2FAParams) bool {
		return string(user.Email) == params.Email &&
			user.FirstName == params.FirstName &&
			user.LastName == params.LastName &&
			validPassword(user.Password, params.Password) &&
			params.Secret != "" && params.Url != "" &&
			params.Url == "otpauth://totp/go-jwt-server:first.last@example.com?algorithm=SHA1&digits=6&issuer=go-jwt-server&period=30&secret="+params.Secret
	})).Return(errors.New("ERROR"))
	twoFaService := twoFA.NewService("go-jwt-server", nil)
	userStorage := NewStorage(query)
	userService := NewService(userStorage, twoFaService, nil)

	res, err := userService.Signup(ctx, user)
	assert.Error(t, err)
	assert.Equal(t, httperror.UserSignUpWith2FAFailed, err.(httperror.HttpError).ErrorCode)
	assert.Empty(t, res)
}

func TestIntegrationService_Login_OK(t *testing.T) {
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

	userQuery := repository.NewMockQuerier(t)
	userQuery.On("GetUserByEmail", ctx, email).
		Return(repository.User{
			Email:     "first.last@example.com",
			FirstName: "First name",
			LastName:  "Last name",
			Password:  "$2a$10$3gF.MeoEsl3lwQiWj24gYe/9abUGois8FAwKMQlhr9grLof6Y1Ryu"},
			nil)

	userStorage := NewStorage(userQuery)
	tokenQuery := token.NewMockQuerier(t)
	tokenStorage := tokens.NewStorage(tokenQuery)
	tokenQuery.On("SaveToken", ctx, mock.MatchedBy(func(token token.SaveTokenParams) bool {
		return token.Token != "" && token.RefreshToken != "" && token.IpAddress == "192.168.1.100" &&
			token.UserAgent == "test" && token.DeviceName == "" && token.CreatedBy == "api"
	})).Return(nil)
	tokenService := tokens.NewService(tokenStorage, []byte("JWT_$€Cr€t"))
	userService := NewService(userStorage, nil, tokenService)
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

func TestIntegrationService_Login_NOK_WrongPassword(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_P@$$word",
	}

	query := repository.NewMockQuerier(t)
	query.On("GetUserByEmail", ctx, email).
		Return(repository.User{
			Email:     "first.last@example.com",
			FirstName: "First name",
			LastName:  "Last name",
			Password:  "$2a$10$3gF.MeoEsl3lwQiWj24gYe/9abUGois8FAwKMQlhr9grLof6Y1Ryu"},
			nil)

	userStorage := NewStorage(query)
	userService := NewService(userStorage, nil, nil)

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

func TestIntegrationService_Login_NOK_DB(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_$trong_P@$$word",
	}

	query := repository.NewMockQuerier(t)
	query.On("GetUserByEmail", ctx, email).Return(repository.User{}, errors.New("sql: no rows in result set"))

	userStorage := NewStorage(query)
	userService := NewService(userStorage, nil, nil)

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

func TestIntegrationService_Login_NOK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_$trong_P@$$word",
	}

	query := repository.NewMockQuerier(t)
	query.On("GetUserByEmail", ctx, email).Return(repository.User{}, errors.New("error"))

	userStorage := NewStorage(query)
	userService := NewService(userStorage, nil, nil)
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

func TestIntegrationService_Login2FA_OK(t *testing.T) {
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
	twoFAQuery.On("Get2FADetails", ctx, userId).Return(twoFARepo.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFAService := twoFA.NewService("go-jwt-server", twoFAStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)

	secret := "JWT_$€CR€T"
	tokenQuery := token.NewMockQuerier(t)
	tokenQuery.On("SaveToken", mock.Anything, mock.Anything).Return(nil)
	tokenStorage := tokens.NewStorage(tokenQuery)
	tokenService := tokens.NewService(tokenStorage, []byte(secret))

	query := repository.NewMockQuerier(t)
	query.On("GetUserById", ctx, userId).Return(repository.User{ID: userId, Email: "first.last@example.com", FirstName: "First", LastName: "Last"}, nil)
	userStorage := NewStorage(query)
	userService := NewService(userStorage, twoFAService, tokenService)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userId, passcode)
	assert.NoError(t, err)
	assert.NotEmpty(t, login2FA)
	assert.NotEmpty(t, login2FA.AccessToken)
	assert.NotEmpty(t, login2FA.RefreshToken)
}

func TestIntegrationService_Login2FA_NOK_UserLocked(t *testing.T) {
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
	twoFAQuery.On("Get2FADetails", ctx, userId).Return(twoFARepo.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFAService := twoFA.NewService("go-jwt-server", twoFAStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)

	query := repository.NewMockQuerier(t)
	query.On("GetUserById", ctx, userId).Return(repository.User{ID: userId, Email: "first.last@example.com", FirstName: "First", LastName: "Last", Locked: true}, nil)
	userStorage := NewStorage(query)
	userService := NewService(userStorage, twoFAService, nil)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userId, passcode)
	assert.Error(t, err)
	assert.Equal(t, httperror.UserAccountLocked, err.(httperror.HttpError).ErrorCode)
	assert.Empty(t, login2FA)
}

func TestIntegrationService_Login2FA_NOK_UserNotExist(t *testing.T) {
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
	twoFAQuery.On("Get2FADetails", ctx, userId).Return(twoFARepo.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFAService := twoFA.NewService("go-jwt-server", twoFAStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)

	query := repository.NewMockQuerier(t)
	query.On("GetUserById", ctx, userId).Return(repository.User{}, errors.New("sql: no rows in result set"))
	userStorage := NewStorage(query)
	userService := NewService(userStorage, twoFAService, nil)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userId, passcode)
	assert.Error(t, err)
	assert.Equal(t, httperror.InvalidCredentials, err.(httperror.HttpError).ErrorCode)
	assert.Empty(t, login2FA)
}

func TestIntegrationService_Login2FA_NOK_UserGetError(t *testing.T) {
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
	twoFAQuery.On("Get2FADetails", ctx, userId).Return(twoFARepo.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFAService := twoFA.NewService("go-jwt-server", twoFAStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-20*time.Second))
	assert.NoError(t, err)

	query := repository.NewMockQuerier(t)
	query.On("GetUserById", ctx, userId).Return(repository.User{}, errors.New("error"))
	userStorage := NewStorage(query)
	userService := NewService(userStorage, twoFAService, nil)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userId, passcode)
	assert.Error(t, err)
	assert.Equal(t, httperror.UndefinedErrorCode, err.(httperror.HttpError).ErrorCode)
	assert.Empty(t, login2FA)
}

func TestIntegrationService_Login2FA_NOK_Old2FACode(t *testing.T) {
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
	twoFAQuery.On("Get2FADetails", ctx, userId).Return(twoFARepo.Users2fa{Secret: "2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ"}, nil)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFAService := twoFA.NewService("go-jwt-server", twoFAStorage)

	passcode, err := totp.GenerateCode("2Q3WE3WTYG7PYGI6B3UVA6GHSMIMHHDZ", time.Now().Add(-60*time.Second))
	assert.NoError(t, err)

	userService := NewService(nil, twoFAService, nil)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userId, passcode)
	assert.Error(t, err)
	assert.Equal(t, httperror.InvalidTwoFA, err.(httperror.HttpError).ErrorCode)
	assert.Empty(t, login2FA)
}
