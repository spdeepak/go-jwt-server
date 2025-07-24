package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
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
	"github.com/spdeepak/go-jwt-server/middleware"
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
	router.Use(middleware.ErrorMiddleware)
	router.Use(middleware.GinLogger())
	router.Use(middleware.JWTAuthMiddleware([]byte("JWT_$€Cr€t"), nil))
	server := NewServer(userService, rolesService, permissionService, tokenService, twoFaService)
	api.RegisterHandlers(router, server)

	// Run all tests
	_, err = dba.DB.Exec(`
        TRUNCATE TABLE
            users_2fa,
            users_password,
            users,
            tokens,
            permissions
        RESTART IDENTITY CASCADE
    `)
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
	truncateTables(t, dba.DB)
	req, _ := http.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_GetLive(t *testing.T) {
	truncateTables(t, dba.DB)
	req, _ := http.NewRequest(http.MethodGet, "/live", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_Signup_OK(t *testing.T) {
	truncateTables(t, dba.DB)
	signup2FADisabled(t)
}

func TestServer_Signup_OK_2FA(t *testing.T) {
	truncateTables(t, dba.DB)
	signup2FAEnabled(t)
}

func TestServer_Signup_NOK_InvalidPassword(t *testing.T) {
	truncateTables(t, dba.DB)
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
	assert.NotNil(t, req)
	assert.NoError(t, err)
	req.Header.Set("User-Agent", "api-test")
	assert.NoError(t, err)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotEmpty(t, rec.Body.String())
	var resErr httperror.HttpError
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resErr))
	assert.Equal(t, "Password doesn't meet requirements", resErr.Description)
}

func TestServer_Signup_NOK_InvalidRequestBody(t *testing.T) {
	truncateTables(t, dba.DB)
	signupBytes, err := json.Marshal(`{"email":"first.last","firstName":"First","lastName":"Last"}`)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(signupBytes))
	assert.NotNil(t, req)
	assert.NoError(t, err)
	req.Header.Set("User-Agent", "api-test")
	assert.NoError(t, err)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotEmpty(t, rec.Body.String())
	var resErr httperror.HttpError
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resErr))
	assert.Equal(t, httperror.InvalidRequestBody, resErr.ErrorCode)
}

func TestServer_Signup_NOK_Duplicate(t *testing.T) {
	truncateTables(t, dba.DB)
	signup2FADisabled(t)

	signupBytes, err := json.Marshal(api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First",
		LastName:     "Last",
		Password:     "$trong_P@$$w0rd",
		TwoFAEnabled: false,
	})
	assert.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(signupBytes))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusConflict, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
	var resErr httperror.HttpError
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &resErr))
	assert.Equal(t, httperror.UserAlreadyExists, resErr.ErrorCode)
}

func TestServer_Login_OK_No2FA(t *testing.T) {
	truncateTables(t, dba.DB)
	//Signup
	signup2FADisabled(t)
	//Login
	login2FADisabled(t)
}

func TestServer_Login_2FA_OK(t *testing.T) {
	truncateTables(t, dba.DB)
	//Signup
	signupRes := signup2FAEnabled(t)

	//Login to get temp_token
	res := login2FAEnabledTempToken(t)

	//Login with temp_token and 2FA code to get Bearer and Refresh token
	generateCode, err := totp.GenerateCode(signupRes.Secret, time.Now())
	assert.NoError(t, err)
	loginWithTempToken2FACode(t, generateCode, res)
}

func TestServer_Login_2FA_NOK_Expired2FA(t *testing.T) {
	truncateTables(t, dba.DB)
	//Signup
	signupRes := signup2FAEnabled(t)

	//Login to get temp_token
	res := login2FAEnabledTempToken(t)

	//Login with temp_token and 2FA code to get Bearer and Refresh token
	generateCode, err := totp.GenerateCode(signupRes.Secret, time.Now().Add(-100*time.Minute))
	assert.NoError(t, err)
	login2faBytes, err := json.Marshal(api.Login2FARequest{
		TwoFACode: generateCode,
	})
	request, err := http.NewRequest(http.MethodPost, "/api/v1/auth/2fa/login", bytes.NewReader(login2faBytes))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("x-login-source", "api-test")
	request.Header.Set("Authorization", "Bearer "+res.TempToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
	var resErr httperror.HttpError
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &resErr))
	assert.Equal(t, httperror.InvalidTwoFA, resErr.ErrorCode)
}

func TestServer_Login_2FA_NOK_InvalidRequestBody(t *testing.T) {
	truncateTables(t, dba.DB)
	//Signup
	signup2FAEnabled(t)

	//Login to get temp_token
	res := login2FAEnabledTempToken(t)

	//Login with temp_token and 2FA code to get Bearer and Refresh token
	login2faBytes, err := json.Marshal(`{}`)
	request, err := http.NewRequest(http.MethodPost, "/api/v1/auth/2fa/login", bytes.NewReader(login2faBytes))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("x-login-source", "api-test")
	request.Header.Set("Authorization", "Bearer "+res.TempToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
	var resErr httperror.HttpError
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &resErr))
	assert.Equal(t, httperror.InvalidRequestBody, resErr.ErrorCode)
}

func TestServer_Login_NOK_RequestBody(t *testing.T) {
	truncateTables(t, dba.DB)
	loginBytes, err := json.Marshal(`{
		"email":    "first.last@example.com",
	}`)
	assert.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBytes))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("x-login-source", "api-test")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
	var resErr httperror.HttpError
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &resErr))
	assert.Equal(t, httperror.InvalidRequestBody, resErr.ErrorCode)
}

func TestServer_Refresh_OK(t *testing.T) {
	truncateTables(t, dba.DB)
	//Signup
	signup2FADisabled(t)

	//Login
	res := login2FADisabled(t)

	//Refresh
	refreshBytes, err := json.Marshal(api.Refresh{
		RefreshToken: res.RefreshToken,
	})
	assert.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(refreshBytes))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("x-login-source", "api-test")
	request.Header.Set("Authorization", "Bearer "+res.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	//respBody := recorder.Body.Bytes()
	//This test fails if I remove the below line because Gin’s ctx.JSON(...) writes to the underlying http.ResponseWriter.
	//In test mode (httptest.NewRecorder()), the response is buffered until router.ServeHTTP(...) completes.
	//Fixing the issue by accessing the object, which triggers Gin or Go’s internal logic to fully marshal and write it.
	//fmt.Printf("--%s--\n", string(respBody))
	//assert.NotEmpty(t, respBody)
	assert.NotEmpty(t, recorder.Body.String())
	var refreshResp api.LoginSuccessWithJWT
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &refreshResp))
	assert.NotEmpty(t, refreshResp)
	assert.NotEmpty(t, refreshResp.RefreshToken)
	assert.NotEmpty(t, refreshResp.AccessToken)
}

func TestServer_Refresh_NOK(t *testing.T) {
	truncateTables(t, dba.DB)
	//Signup
	signup2FADisabled(t)

	//Login
	res := login2FADisabled(t)

	//Refresh
	refreshBytes, err := json.Marshal(``)
	assert.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(refreshBytes))
	assert.NoError(t, err)
	assert.NotNil(t, request)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("x-login-source", "api-test")
	request.Header.Set("Authorization", "Bearer "+res.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
	var resErr httperror.HttpError
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &resErr))
	assert.Equal(t, httperror.InvalidRequestBody, resErr.ErrorCode)
}

func TestServer_RevokeRefreshToken_OK(t *testing.T) {
	truncateTables(t, dba.DB)
	//Signup
	signup2FADisabled(t)

	//Login
	res := login2FADisabled(t)

	//Revoke refresh token
	revokeBytes, err := json.Marshal(api.RevokeCurrentSession{
		RefreshToken: res.RefreshToken,
	})
	assert.NoError(t, err)
	request, err := http.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/current", bytes.NewReader(revokeBytes))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+res.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}

func TestServer_RevokeRefreshToken_NOK_InvalidRequestBody(t *testing.T) {
	truncateTables(t, dba.DB)
	//Signup
	signup2FADisabled(t)

	//Login
	res := login2FADisabled(t)

	//Revoke refresh token
	revokeBytes, err := json.Marshal(``)
	assert.NoError(t, err)
	request, err := http.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/current", bytes.NewReader(revokeBytes))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+res.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
	var resErr httperror.HttpError
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &resErr))
	assert.Equal(t, httperror.InvalidRequestBody, resErr.ErrorCode)
}

func TestServer_Create2FA_OK(t *testing.T) {
	truncateTables(t, dba.DB)
	//Signup
	signup2FADisabled(t)

	//Login
	loginResp := login2FADisabled(t)

	//Create 2FA
	request, err := http.NewRequest(http.MethodPost, "/api/v1/auth/2fa/setup", nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("x-login-source", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusCreated, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
	var twoFaResponse api.TwoFAResponse
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &twoFaResponse))
	assert.NotEmpty(t, twoFaResponse)
	assert.NotEmpty(t, twoFaResponse.Secret)
	assert.NotEmpty(t, twoFaResponse.QrImage)
}

func TestServer_Remove2FA_OK(t *testing.T) {
	truncateTables(t, dba.DB)
	//Signup
	signupRes := signup2FAEnabled(t)

	//Login to get temp_token
	res := login2FAEnabledTempToken(t)

	//Login with temp_token and 2FA code to get Bearer and Refresh token
	generateCode, err := totp.GenerateCode(signupRes.Secret, time.Now())
	assert.NoError(t, err)
	twoFaLoginResp := loginWithTempToken2FACode(t, generateCode, res)

	//Remove 2FA
	generateCode, err = totp.GenerateCode(signupRes.Secret, time.Now())
	assert.NoError(t, err)
	twoFABytes, err := json.Marshal(api.Remove2FARequest{
		TwoFACode: generateCode,
	})
	assert.NoError(t, err)
	request, err := http.NewRequest(http.MethodDelete, "/api/v1/auth/2fa", bytes.NewReader(twoFABytes))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("x-login-source", "api-test")
	request.Header.Set("Authorization", "Bearer "+twoFaLoginResp.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}

func TestServer_RevokeAllTokens_OK(t *testing.T) {
	truncateTables(t, dba.DB)
	//Signup
	truncateTables(t, dba.DB)
	signup2FADisabled(t)

	//Login
	res := login2FADisabled(t)

	//Remove 2FA
	request, err := http.NewRequest(http.MethodDelete, "/api/v1/auth/sessions", nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("x-login-source", "api-test")
	request.Header.Set("Authorization", "Bearer "+res.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}

func TestServer_CreateNewRole_OK(t *testing.T) {
	truncateTables(t, dba.DB)
	//Signup
	signup2FADisabled(t)
	//Login
	res := login2FADisabled(t)
	//Create a new Role
	createRole(t, res)
}

func signup2FADisabled(t *testing.T) {
	signupBytes, err := json.Marshal(api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First",
		LastName:     "Last",
		Password:     "$trong_P@$$w0rd",
		TwoFAEnabled: false,
	})
	assert.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(signupBytes))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusCreated, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}

func signup2FAEnabled(t *testing.T) api.SignUpWith2FAResponse {
	signupBytes, err := json.Marshal(api.UserSignup{
		Email:        "first.last@example.com",
		FirstName:    "First",
		LastName:     "Last",
		Password:     "$trong_P@$$w0rd",
		TwoFAEnabled: true,
	})
	assert.NoError(t, err)

	request, err := http.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewReader(signupBytes))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusCreated, recorder.Code)
	assert.NotEmpty(t, recorder.Body)
	assert.NotEmpty(t, recorder.Body.String())

	var res api.SignUpWith2FAResponse
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))
	assert.NotEmpty(t, res.Secret)
	assert.NotEmpty(t, res.QrImage)
	return res
}

func login2FADisabled(t *testing.T) api.LoginSuccessWithJWT {
	loginBytes, err := json.Marshal(api.UserLogin{
		Email:    "first.last@example.com",
		Password: "$trong_P@$$w0rd",
	})
	assert.NoError(t, err)

	request, err := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBytes))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("x-login-source", "api-test")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())

	var res api.LoginSuccessWithJWT
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))
	assert.NotEmpty(t, res.RefreshToken)
	assert.NotEmpty(t, res.AccessToken)

	return res
}

func login2FAEnabledTempToken(t *testing.T) api.LoginRequires2FA {
	loginBytes, err := json.Marshal(api.UserLogin{
		Email:    "first.last@example.com",
		Password: "$trong_P@$$w0rd",
	})
	assert.NoError(t, err)

	request, err := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBytes))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("x-login-source", "api-test")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())

	var res api.LoginRequires2FA
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))
	assert.NotEmpty(t, res)
	assert.NotEmpty(t, res.TempToken)
	assert.NotEmpty(t, res.Type)
	assert.Equal(t, api.N2fa, res.Type)

	return res
}

func loginWithTempToken2FACode(t *testing.T, generateCode string, res api.LoginRequires2FA) api.LoginSuccessWithJWT {
	login2faBytes, err := json.Marshal(api.Login2FARequest{
		TwoFACode: generateCode,
	})

	request, err := http.NewRequest(http.MethodPost, "/api/v1/auth/2fa/login", bytes.NewReader(login2faBytes))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("x-login-source", "api-test")
	request.Header.Set("Authorization", "Bearer "+res.TempToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())

	var twoFaLoginResp api.LoginSuccessWithJWT
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &twoFaLoginResp))
	assert.NotEmpty(t, twoFaLoginResp)
	assert.NotEmpty(t, twoFaLoginResp.RefreshToken)
	assert.NotEmpty(t, twoFaLoginResp.AccessToken)

	return twoFaLoginResp
}

func createRole(t *testing.T, res api.LoginSuccessWithJWT) api.RoleResponse {
	createRole, err := json.Marshal(api.CreateRole{
		Description: "role description",
		Name:        "admin_role",
	})
	assert.NoError(t, err)

	request, err := http.NewRequest(http.MethodPost, "/api/v1/access-control/roles", bytes.NewReader(createRole))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+res.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusCreated, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())

	var roleResponse api.RoleResponse
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &roleResponse))
	assert.Equal(t, "role description", roleResponse.Description)
	assert.Equal(t, "admin_role", roleResponse.Name)
	assert.IsType(t, uuid.UUID{}, roleResponse.Id)
	assert.Equal(t, "first.last@example.com", roleResponse.CreatedBy)
	assert.NotNil(t, roleResponse.CreatedAt)

	return roleResponse
}
