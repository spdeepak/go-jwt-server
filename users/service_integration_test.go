package users

import (
	"context"
	"database/sql"
	"log"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/config"
	"github.com/spdeepak/go-jwt-server/db"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/tokens"
	tokenRepo "github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/spdeepak/go-jwt-server/twoFA"
	twoFARepo "github.com/spdeepak/go-jwt-server/twoFA/repository"
	"github.com/spdeepak/go-jwt-server/users/repository"
)

var userStorage Storage
var tokenStorage tokens.Storage
var twoFAStorage twoFA.Storage
var dba *db.Database

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
	dba = dbConnection
	db.RunMigrationQueries(dbConnection, "../migrations")
	query := repository.New(dbConnection.DB)
	userStorage = NewStorage(query)
	tokenQuery := tokenRepo.New(dbConnection.DB)
	tokenStorage = tokens.NewStorage(tokenQuery)
	twoFAQuery := twoFARepo.New(dbConnection.DB)
	twoFAStorage = twoFA.NewStorage(twoFAQuery)
	// Run all tests
	code := m.Run()

	// Optional: Clean up (e.g., drop DB or close connection)
	_ = dbConnection.DB.Close()
	os.Exit(code)
}

func truncateTables(t *testing.T, db *sql.DB) {
	_, err := db.Exec(`
        TRUNCATE TABLE
            users_2fa,
            users_password,
            users,
            tokens
        RESTART IDENTITY CASCADE
    `)
	assert.NoError(t, err)
}

func TestIntegrationService_Signup_No2FA(t *testing.T) {
	t.Run("Create New User without 2FA", func(t *testing.T) {
		signup_No2fa_OK(t)
	})
	t.Run("Create User already exists without 2FA", func(t *testing.T) {
		signup_No2FA_NOK_UserAlreadyExists(t)
	})
	truncateTables(t, dba.DB)
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

func TestIntegrationService_Signup_2FA(t *testing.T) {
	t.Run("Create New User with 2FA", func(t *testing.T) {
		signup_2FA_OK(t)
	})
	t.Run("Create User already exists with 2FA", func(t *testing.T) {
		signup_2FA_NOK_UserAlreadyExists(t)
	})
	truncateTables(t, dba.DB)
}

func signup_2FA_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First name",
		LastName:     "Last name",
		Password:     "Som€_$trong_P@$$word",
		TwoFAEnabled: true,
	}

	twoFaService := twoFA.NewService("go-jwt-server", nil)
	userService := NewService(userStorage, twoFaService, nil)

	res, err := userService.Signup(ctx, user)
	assert.NoError(t, err)
	assert.NotEmpty(t, res)
	assert.NotEmpty(t, res.Secret)
	assert.NotEmpty(t, res.QrImage)
}

func signup_2FA_NOK_UserAlreadyExists(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First name",
		LastName:     "Last name",
		Password:     "Som€_$trong_P@$$word",
		TwoFAEnabled: true,
	}

	twoFaService := twoFA.NewService("go-jwt-server", nil)
	userService := NewService(userStorage, twoFaService, nil)

	res, err := userService.Signup(ctx, user)
	assert.Error(t, err)
	assert.Equal(t, httperror.UserAlreadyExists, err.(httperror.HttpError).ErrorCode)
	assert.Empty(t, res)
}

func TestIntegrationService_Login_OK(t *testing.T) {
	t.Run("Login without 2FA", func(t *testing.T) {
		signup_No2fa_OK(t)
		login_OK(t)
	})
	t.Run("Login with 2FA invalid password", func(t *testing.T) {
		login_NOK_WrongPassword(t)
	})
	truncateTables(t, dba.DB)
	t.Run("Login with 2FA invalid user", func(t *testing.T) {
		login_NOK(t)
	})
}

func login_OK(t *testing.T) {
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

func login_NOK_WrongPassword(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_P@$$word",
	}

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

func login_NOK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	email := "first.last@example.com"
	userLogin := api.UserLogin{
		Email:    email,
		Password: "Som€_$trong_P@$$word",
	}

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

func TestIntegrationService_Login2FA(t *testing.T) {
	t.Run("Login with 2FA", func(t *testing.T) {
		login2FA_OK(t)
	})
	truncateTables(t, dba.DB)
	t.Run("Login with expired 2FA", func(t *testing.T) {
		login2FA_NOK_Old2FACode(t)
	})
	truncateTables(t, dba.DB)
	t.Run("Login with expired 2FA", func(t *testing.T) {
		login2FA_NOK_UserNotExist(t)
	})
}

func login2FA_OK(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First name",
		LastName:     "Last name",
		Password:     "Som€_$trong_P@$$word",
		TwoFAEnabled: true,
	}

	secret := "JWT_$€CR€T"
	tokenService := tokens.NewService(tokenStorage, []byte(secret))
	twoFaService := twoFA.NewService("go-jwt-server", twoFAStorage)
	userService := NewService(userStorage, twoFaService, tokenService)

	res, err := userService.Signup(ctx, user)
	assert.NoError(t, err)
	assert.NotEmpty(t, res)
	assert.NotEmpty(t, res.Secret)
	assert.NotEmpty(t, res.QrImage)

	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	userByEmail, err := userStorage.GetUserByEmail(context.Background(), "first.last@example.com")
	assert.NoError(t, err)

	passcode, err := totp.GenerateCode(res.Secret, time.Now().Add(-20*time.Second))
	assert.NoError(t, err)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userByEmail.ID, passcode)
	assert.NoError(t, err)
	assert.NotEmpty(t, login2FA)
	assert.NotEmpty(t, login2FA.AccessToken)
	assert.NotEmpty(t, login2FA.RefreshToken)
}

func login2FA_NOK_Old2FACode(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	user := api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First name",
		LastName:     "Last name",
		Password:     "Som€_$trong_P@$$word",
		TwoFAEnabled: true,
	}

	secret := "JWT_$€CR€T"
	tokenService := tokens.NewService(tokenStorage, []byte(secret))
	twoFaService := twoFA.NewService("go-jwt-server", twoFAStorage)
	userService := NewService(userStorage, twoFaService, tokenService)

	res, err := userService.Signup(ctx, user)
	assert.NoError(t, err)
	assert.NotEmpty(t, res)
	assert.NotEmpty(t, res.Secret)
	assert.NotEmpty(t, res.QrImage)

	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	userByEmail, err := userStorage.GetUserByEmail(context.Background(), "first.last@example.com")
	assert.NoError(t, err)

	passcode, err := totp.GenerateCode(res.Secret, time.Now().Add(-60*time.Second))
	assert.NoError(t, err)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userByEmail.ID, passcode)
	assert.Error(t, err)
	assert.Empty(t, login2FA)
}

func login2FA_NOK_UserNotExist(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	secret := "JWT_$€CR€T"
	tokenService := tokens.NewService(tokenStorage, []byte(secret))
	twoFaService := twoFA.NewService("go-jwt-server", twoFAStorage)
	userService := NewService(userStorage, twoFaService, tokenService)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, uuid.New(), "123456")
	assert.Error(t, err)
	assert.Empty(t, login2FA)
}
