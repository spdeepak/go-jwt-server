package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/config"
	"github.com/spdeepak/go-jwt-server/db"
	"github.com/spdeepak/go-jwt-server/permissions"
	permissionsRepo "github.com/spdeepak/go-jwt-server/permissions/repository"
	"github.com/spdeepak/go-jwt-server/roles"
	roleRepo "github.com/spdeepak/go-jwt-server/roles/repository"
	"github.com/spdeepak/go-jwt-server/tokens"
	tokenRepo "github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/spdeepak/go-jwt-server/twoFA"
	twoFARepo "github.com/spdeepak/go-jwt-server/twoFA/repository"
	"github.com/spdeepak/go-jwt-server/users"
	"github.com/spdeepak/go-jwt-server/users/repository"
)

var router *gin.Engine
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
	db.RunMigrationQueries(dbConnection, "../../migrations")
	twoFAQuery := twoFARepo.New(dbConnection.DB)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFaService := twoFA.NewService("go-jwt-server", twoFAStorage)
	tokenQuery := tokenRepo.New(dbConnection.DB)
	tokenStorage := tokens.NewStorage(tokenQuery)
	tokenService := tokens.NewService(tokenStorage, []byte("JWT_$€Cr€t"))
	userQuery := repository.New(dbConnection.DB)
	userStorage := users.NewStorage(userQuery)
	userService := users.NewService(userStorage, twoFaService, tokenService)
	roleQuery := roleRepo.New(dbConnection.DB)
	roleStorage := roles.NewStorage(roleQuery)
	rolesService := roles.NewService(roleStorage)
	permissionQuery := permissionsRepo.New(dbConnection.DB)
	permissionStorage := permissions.NewStorage(permissionQuery)
	permissionService := permissions.NewService(permissionStorage)
	//Setup router
	swagger, _ := api.GetSwagger()
	swagger.Servers = nil
	router = gin.New()
	server := NewServer(userService, rolesService, permissionService, tokenService, twoFaService)
	api.RegisterHandlers(router, server)
	// Run all tests
	code := m.Run()

	// Optional: Clean up (e.g., drop DB or close connection)
	_ = dbConnection.DB.Close()
	_ = dba.DB.Close()
	os.Exit(code)
}

func truncateTables(t *testing.T, db *sql.DB) {
	_, err := db.Exec(`
        TRUNCATE TABLE
            users_2fa,
            users_password,
            users,
            tokens,
            roles,
            permissions,
            role_permissions,
            user_permissions
        RESTART IDENTITY CASCADE
    `)
	assert.NoError(t, err)
}

func TestServer_GetReady(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_GetLive(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/live", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_Signup_OK(t *testing.T) {
	signup := api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First",
		LastName:     "Last",
		Password:     "$trong_P@$$w0rd",
		TwoFAEnabled: false,
	}
	signupBytes, err := json.Marshal(signup)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(signupBytes))
	req.Header.Set("User-Agent", "api-test")
	assert.NoError(t, err)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Empty(t, rec.Body.String())

	truncateTables(t, dba.DB)
}

func TestServer_Signup_OK_2FA(t *testing.T) {
	signup := api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First",
		LastName:     "Last",
		Password:     "$trong_P@$$w0rd",
		TwoFAEnabled: true,
	}
	signupBytes, err := json.Marshal(signup)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(signupBytes))
	req.Header.Set("User-Agent", "api-test")
	assert.NoError(t, err)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.NotEmpty(t, rec.Body)
	assert.NotEmpty(t, rec.Body.String())
	var res api.SignUpWith2FAResponse
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.NotEmpty(t, res.Secret)
	assert.NotEmpty(t, res.QrImage)

	truncateTables(t, dba.DB)
}

func TestServer_Signup_NOK_Password(t *testing.T) {
	signup := api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First",
		LastName:     "Last",
		Password:     "stringpassword",
		TwoFAEnabled: false,
	}
	signupBytes, err := json.Marshal(signup)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(signupBytes))
	req.Header.Set("User-Agent", "api-test")
	assert.NoError(t, err)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, rec.Body.String())
}

func TestServer_Signup_NOK_BadRequestBody(t *testing.T) {
	signupBytes, err := json.Marshal(`{"email":"first.last","firstName":"First","lastName":"Last"}`)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(signupBytes))
	req.Header.Set("User-Agent", "api-test")
	assert.NoError(t, err)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, rec.Body.String())
}

func TestServer_Signup_NOK_Duplicate(t *testing.T) {
	signupBytes, err := json.Marshal(api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First",
		LastName:     "Last",
		Password:     "$trong_P@$$w0rd",
		TwoFAEnabled: false,
	})
	assert.NoError(t, err)
	req1, err := http.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(signupBytes))
	assert.NotNil(t, req1)
	assert.NoError(t, err)
	req1.Header.Set("User-Agent", "api-test")
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusCreated, rec1.Code)
	assert.Empty(t, rec1.Body.String())

	signupBytes, err = json.Marshal(api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First",
		LastName:     "Last",
		Password:     "$trong_P@$$w0rd",
		TwoFAEnabled: false,
	})
	assert.NoError(t, err)
	req2, err := http.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(signupBytes))
	assert.NotNil(t, req2)
	assert.NoError(t, err)
	req2.Header.Set("User-Agent", "api-test")
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusConflict, rec2.Code)
	assert.Empty(t, rec2.Body.String())

	truncateTables(t, dba.DB)
}

func TestServer_Login_OK_No2FA(t *testing.T) {
	signupBytes, err := json.Marshal(api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First",
		LastName:     "Last",
		Password:     "$trong_P@$$w0rd",
		TwoFAEnabled: false,
	})
	assert.NoError(t, err)
	req1, err := http.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(signupBytes))
	assert.NotNil(t, req1)
	assert.NoError(t, err)
	req1.Header.Set("User-Agent", "api-test")
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusCreated, rec1.Code)
	assert.Empty(t, rec1.Body.String())

	loginBytes, err := json.Marshal(api.UserLogin{
		Email:    "first.last@example.com",
		Password: "$trong_P@$$w0rd",
	})
	assert.NoError(t, err)
	req2, err := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBytes))
	assert.NotNil(t, req2)
	assert.NoError(t, err)
	req2.Header.Set("User-Agent", "api-test")
	req2.Header.Set("x-login-source", "api-test")
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.NotEmpty(t, rec2.Body.String())
	var res api.LoginSuccessWithJWT
	assert.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &res))
	assert.NotEmpty(t, res.RefreshToken)
	assert.NotEmpty(t, res.AccessToken)

	truncateTables(t, dba.DB)
}

func TestServer_Login_OK_2FA(t *testing.T) {
	signupBytes, err := json.Marshal(api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First",
		LastName:     "Last",
		Password:     "$trong_P@$$w0rd",
		TwoFAEnabled: true,
	})
	assert.NoError(t, err)
	req1, err := http.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(signupBytes))
	assert.NotNil(t, req1)
	assert.NoError(t, err)
	req1.Header.Set("User-Agent", "api-test")
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusCreated, rec1.Code)
	assert.NotEmpty(t, rec1.Body.String())
	var signupRes api.SignUpWith2FAResponse
	assert.NoError(t, json.Unmarshal(rec1.Body.Bytes(), &signupRes))
	assert.NotEmpty(t, signupRes.QrImage)
	assert.NotEmpty(t, signupRes.Secret)

	loginBytes, err := json.Marshal(api.UserLogin{
		Email:    "first.last@example.com",
		Password: "$trong_P@$$w0rd",
	})
	assert.NoError(t, err)
	req2, err := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBytes))
	assert.NotNil(t, req2)
	assert.NoError(t, err)
	req2.Header.Set("User-Agent", "api-test")
	req2.Header.Set("x-login-source", "api-test")
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.NotEmpty(t, rec2.Body.String())
	var res api.LoginRequires2FA
	assert.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &res))
	assert.NotEmpty(t, res)
	assert.NotEmpty(t, res.TempToken)
	assert.NotEmpty(t, res.Type)
	assert.Equal(t, api.N2fa, res.Type)

	truncateTables(t, dba.DB)
}

func TestServer_Login_NOK_RequestBody(t *testing.T) {
	loginBytes, err := json.Marshal(`{
		"email":    "first.last@example.com",
	}`)
	assert.NoError(t, err)
	req2, err := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBytes))
	assert.NotNil(t, req2)
	assert.NoError(t, err)
	req2.Header.Set("User-Agent", "api-test")
	req2.Header.Set("x-login-source", "api-test")
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusBadRequest, rec2.Code)
	assert.Empty(t, rec2.Body.String())
}

func TestServer_Refresh_OK(t *testing.T) {
	//Signup
	signupBytes, err := json.Marshal(api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First",
		LastName:     "Last",
		Password:     "$trong_P@$$w0rd",
		TwoFAEnabled: false,
	})
	assert.NoError(t, err)
	req1, err := http.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(signupBytes))
	assert.NotNil(t, req1)
	assert.NoError(t, err)
	req1.Header.Set("User-Agent", "api-test")
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusCreated, rec1.Code)
	assert.Empty(t, rec1.Body.String())

	//Login
	loginBytes, err := json.Marshal(api.UserLogin{
		Email:    "first.last@example.com",
		Password: "$trong_P@$$w0rd",
	})
	assert.NoError(t, err)
	req2, err := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBytes))
	assert.NotNil(t, req2)
	assert.NoError(t, err)
	req2.Header.Set("User-Agent", "api-test")
	req2.Header.Set("x-login-source", "api-test")
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.NotEmpty(t, rec2.Body.String())
	var res api.LoginSuccessWithJWT
	assert.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &res))
	assert.NotEmpty(t, res.RefreshToken)
	assert.NotEmpty(t, res.AccessToken)

	//Refresh
	refreshBytes, err := json.Marshal(api.Refresh{
		RefreshToken: res.RefreshToken,
	})
	assert.NoError(t, err)
	req3, err := http.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(refreshBytes))
	assert.NotNil(t, req3)
	assert.NoError(t, err)
	req3.Header.Set("User-Agent", "api-test")
	req3.Header.Set("x-login-source", "api-test")
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusOK, rec3.Code)
	respBody := rec3.Body.Bytes()
	fmt.Printf("--%s--\n", string(respBody))
	assert.NotEmpty(t, respBody)
	var refreshResp api.LoginSuccessWithJWT
	assert.NoError(t, json.Unmarshal(rec3.Body.Bytes(), &refreshResp))
	assert.NotEmpty(t, refreshResp)
	assert.NotEmpty(t, refreshResp.RefreshToken)
	assert.NotEmpty(t, refreshResp.AccessToken)

	truncateTables(t, dba.DB)
}

func TestServer_Refresh_NOK(t *testing.T) {
	refreshBytes, err := json.Marshal(``)
	assert.NoError(t, err)
	req3, err := http.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(refreshBytes))
	assert.NoError(t, err)
	assert.NotNil(t, req3)
	req3.Header.Set("User-Agent", "api-test")
	req3.Header.Set("x-login-source", "api-test")
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusBadRequest, rec3.Code)
	assert.Empty(t, rec3.Body.String())
}
