package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/config"
	"github.com/spdeepak/go-jwt-server/internal/db"
	"github.com/spdeepak/go-jwt-server/internal/error"
	"github.com/spdeepak/go-jwt-server/internal/permissions"
	permissionsRepo "github.com/spdeepak/go-jwt-server/internal/permissions/repository"
	"github.com/spdeepak/go-jwt-server/internal/roles"
	roleRepo "github.com/spdeepak/go-jwt-server/internal/roles/repository"
	"github.com/spdeepak/go-jwt-server/internal/tokens"
	tokenRepo "github.com/spdeepak/go-jwt-server/internal/tokens/repository"
	"github.com/spdeepak/go-jwt-server/internal/twoFA"
	twoFARepo "github.com/spdeepak/go-jwt-server/internal/twoFA/repository"
	"github.com/spdeepak/go-jwt-server/internal/users"
	usersRepo "github.com/spdeepak/go-jwt-server/internal/users/repository"
	"github.com/spdeepak/go-jwt-server/middleware"
	"github.com/spdeepak/go-jwt-server/util"
)

var router *gin.Engine
var dbConfig = config.PostgresConfig{
	Host:              "localhost",
	Port:              "5432",
	DBName:            "jwt_server",
	UserName:          "admin",
	Password:          "admin",
	SSLMode:           "disable",
	Timeout:           5 * time.Second,
	MaxRetry:          5,
	ConnectTimeout:    10 * time.Second,
	StatementTimeout:  15 * time.Second,
	MaxOpenConns:      5,
	MaxIdleConns:      5,
	ConnMaxLifetime:   10 * time.Minute,
	ConnMaxIdleTime:   2 * time.Minute,
	HealthCheckPeriod: 1 * time.Minute,
}

func TestMain(m *testing.M) {
	dbConnection := db.Connect(dbConfig)
	twoFAQuery := twoFARepo.New(dbConnection)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFaService := twoFA.NewService("go-jwt-server", twoFAStorage)
	tokenQuery := tokenRepo.New(dbConnection)
	tokenStorage := tokens.NewStorage(tokenQuery)
	tokenService := tokens.NewService(tokenStorage, []byte("JWT_$€Cr€t"))
	userQuery := usersRepo.New(dbConnection)
	userService := users.NewService(userQuery, twoFaService, tokenService)
	roleQuery := roleRepo.New(dbConnection)
	rolesService := roles.NewService(roleQuery)
	permissionQuery := permissionsRepo.New(dbConnection)
	permissionService := permissions.NewService(permissionQuery)
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
	truncateTables()
	code := m.Run()
	// Clean up (truncate tables)
	truncateTables()
	dbConnection.Close()
	os.Exit(code)
}

func truncateTables() {
	t := &testing.T{}
	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	_, err := dbConnection.Exec(context.Background(), `
        DO $$
			DECLARE
				r RECORD;
			BEGIN
				FOR r IN
					SELECT tablename
					FROM pg_tables
					WHERE schemaname = 'public'
				LOOP
					EXECUTE format('TRUNCATE TABLE public.%I CASCADE;', r.tablename);
				END LOOP;
		END $$;
    `)
	require.NoError(t, err)
}

func resetPublicSchema(pool *pgxpool.Pool) error {
	_, err := pool.Exec(context.Background(), `
        DROP SCHEMA IF EXISTS public CASCADE;
        CREATE SCHEMA public;
    `)
	return err
}

func TestServer_GetReady(t *testing.T) {
	truncateTables()
	req, _ := http.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_GetLive(t *testing.T) {
	truncateTables()
	req, _ := http.NewRequest(http.MethodGet, "/live", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_Signup_OK(t *testing.T) {
	truncateTables()
	signup2FADisabled(t)
}

func TestServer_Signup_OK_2FA(t *testing.T) {
	truncateTables()
	signup2FAEnabled(t)
}

func TestServer_Signup_NOK_InvalidPassword(t *testing.T) {
	truncateTables()
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
	truncateTables()
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
	truncateTables()
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
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	login2FADisabled(t)
}

func TestServer_Login_2FA_OK(t *testing.T) {
	truncateTables()
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
	truncateTables()
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
	truncateTables()
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
	truncateTables()
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
	truncateTables()
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
	truncateTables()
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
	truncateTables()
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
	truncateTables()
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
	truncateTables()
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
	truncateTables()
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
	truncateTables()
	//Signup
	truncateTables()
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
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	res := login2FADisabled(t)
	//Create a new Role
	createRole(t, res, api.CreateRole{
		Description: "role description",
		Name:        "admin_role",
	})
}

func TestServer_GetRoleById_OK(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Role
	roleRes := createRole(t, loginRes, api.CreateRole{
		Description: "role description",
		Name:        "admin_role",
	})
	//Get Role By Id
	getRoleById(t, loginRes, roleRes)

}

func TestServer_GetRoleById_NOK_NotFound(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)

	//Get Role By Id
	getRoleByIdNotFound(t, loginRes, uuid.New().String())
}

func TestServer_ListAllRoles_OK(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Role
	roleRes1 := createRole(t, loginRes, api.CreateRole{
		Description: "role description",
		Name:        "admin_role_1",
	})
	roleRes2 := createRole(t, loginRes, api.CreateRole{
		Description: "role description",
		Name:        "admin_role_2",
	})
	//List All roles
	request, err := http.NewRequest(http.MethodGet, "/api/v1/access-control/roles", nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())

	var roleResponse []api.RoleResponse
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &roleResponse))
	assert.Len(t, roleResponse, 2)
	assert.Contains(t, roleResponse, roleRes1)
	assert.Contains(t, roleResponse, roleRes2)
}

func TestServer_UpdateRoleById_OK(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Role
	roleRes := createRole(t, loginRes, api.CreateRole{
		Description: "role description",
		Name:        "admin_role_1",
	})
	//Update role by ID
	updatedRoleDescription := "role description Updated"
	updateRole, err := json.Marshal(api.UpdateRole{
		Description: &updatedRoleDescription,
	})
	request, err := http.NewRequest(http.MethodPatch, "/api/v1/access-control/roles/"+roleRes.Id.String(), bytes.NewReader(updateRole))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())

	var roleResponse api.RoleResponse
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &roleResponse))
	assert.Equal(t, roleRes.Name, roleResponse.Name)
	assert.Equal(t, updatedRoleDescription, roleResponse.Description)
	assert.Equal(t, roleRes.CreatedAt, roleResponse.CreatedAt)
	assert.Equal(t, roleRes.CreatedBy, roleResponse.CreatedBy)
	assert.NotEqual(t, roleRes.UpdatedAt, roleResponse.UpdatedAt)
	assert.Equal(t, roleRes.UpdatedBy, roleResponse.UpdatedBy)
}

func TestServer_UpdateRoleById_NOK_RoleNotFound(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Role
	roleRes := createRole(t, loginRes, api.CreateRole{
		Description: "role description",
		Name:        "admin_role_1",
	})
	//Delete Role by Id
	deleteRoleById(t, loginRes, roleRes.Id.String())

	//Update role by ID
	updatedRoleDescription := "role description Updated"
	updateRole, err := json.Marshal(api.UpdateRole{
		Description: &updatedRoleDescription,
	})
	request, err := http.NewRequest(http.MethodPatch, "/api/v1/access-control/roles/"+roleRes.Id.String(), bytes.NewReader(updateRole))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusNotFound, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
}

func TestServer_DeleteRoleById_NOK_NotFound(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Role
	roleRes := createRole(t, loginRes, api.CreateRole{
		Description: "role description",
		Name:        "admin_role_1",
	})
	//Delete Role by Id
	deleteRoleById(t, loginRes, roleRes.Id.String())

	//Get Role By ID
	getRoleByIdNotFound(t, loginRes, roleRes.Id.String())
}

func TestServer_CreateNewPermission_OK(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	res := login2FADisabled(t)
	//Create a new Permission
	createPermission(t, res, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission",
	})
}

func TestServer_GetPermissionById_OK(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Permission
	permissionRes := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission",
	})
	//Get Permission By Id
	getPermissionById(t, loginRes, permissionRes)
}

func TestServer_GetPermissionById_NOK_NotFound(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)

	//Get Permission By Id
	getPermissionByIdNotFound(t, loginRes, uuid.New().String())
}

func TestServer_ListAllPermissions_OK(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Permission
	permissionRes1 := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission_1",
	})
	permissionRes2 := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission_2",
	})
	//List All permissions
	request, err := http.NewRequest(http.MethodGet, "/api/v1/access-control/permissions", nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())

	var permissionResponse []api.PermissionResponse
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &permissionResponse))
	assert.Len(t, permissionResponse, 2)
	assert.Contains(t, permissionResponse, permissionRes1)
	assert.Contains(t, permissionResponse, permissionRes2)
}

func TestServer_UpdatePermissionById_OK(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Permission
	permissionRes := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission_1",
	})
	//Update permission by ID
	updatedPermissionDescription := "permission description Updated"
	updatePermission, err := json.Marshal(api.UpdatePermission{
		Description: &updatedPermissionDescription,
	})
	request, err := http.NewRequest(http.MethodPatch, "/api/v1/access-control/permissions/"+permissionRes.Id.String(), bytes.NewReader(updatePermission))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())

	var permissionResponse api.PermissionResponse
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &permissionResponse))
	assert.Equal(t, permissionRes.Name, permissionResponse.Name)
	assert.Equal(t, updatedPermissionDescription, permissionResponse.Description)
	assert.Equal(t, permissionRes.CreatedAt, permissionResponse.CreatedAt)
	assert.Equal(t, permissionRes.CreatedBy, permissionResponse.CreatedBy)
	assert.NotEqual(t, permissionRes.UpdatedAt, permissionResponse.UpdatedAt)
	assert.Equal(t, permissionRes.UpdatedBy, permissionResponse.UpdatedBy)
}

func TestServer_UpdatePermissionById_NOK_PermissionNotFound(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Permission
	permissionRes := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission_1",
	})
	//Delete Permission by Id
	deletePermissionByIdOK(t, loginRes, permissionRes.Id.String())

	//Update permission by ID
	updatedPermissionDescription := "permission description Updated"
	updatePermission, err := json.Marshal(api.UpdatePermission{
		Description: &updatedPermissionDescription,
	})
	request, err := http.NewRequest(http.MethodPatch, "/api/v1/access-control/permissions/"+permissionRes.Id.String(), bytes.NewReader(updatePermission))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusNotFound, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
}

func TestServer_DeletePermissionById_NOK_NotFound(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Permission
	permissionRes := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission_1",
	})
	//Delete Permission by Id
	deletePermissionByIdOK(t, loginRes, permissionRes.Id.String())

	//Get Permission By ID
	getPermissionByIdNotFound(t, loginRes, permissionRes.Id.String())
}

func TestServer_AssignPermissionToRole_OK(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Role
	role := createRole(t, loginRes, api.CreateRole{
		Description: "role description",
		Name:        "admin_role",
	})
	//Create a new Permission
	permissionRes := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission_1",
	})
	//Assign Permission to Role
	assignPermissionToRole(t, permissionRes, role, loginRes)
}

func TestServer_UnassignPermissionFromRole_OK(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Role
	role := createRole(t, loginRes, api.CreateRole{
		Description: "role description",
		Name:        "admin_role",
	})
	//Create a new Permission
	permissionRes := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission_1",
	})
	//Assign Permission to Role
	assignPermissionToRole(t, permissionRes, role, loginRes)
	//Unassign Permission to Role
	unassignPermissionToRole(t, permissionRes, role, loginRes)
}

func TestServer_RolesAndPermissions_OK(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Role
	role := createRole(t, loginRes, api.CreateRole{
		Description: "role description",
		Name:        "admin_role",
	})
	//Create a new Permission
	permissionRes1 := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission_1",
	})
	permissionRes2 := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission_2",
	})
	//Assign Permission to Role
	assignPermissionToRole(t, permissionRes1, role, loginRes)
	assignPermissionToRole(t, permissionRes2, role, loginRes)
	//List Roles and Permissions
	request, err := http.NewRequest(http.MethodGet, "/api/v1/access-control/roles/permissions", nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())

	var rolesAndPermissions []api.RolesAndPermissionResponse
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &rolesAndPermissions))
	assert.NotEmpty(t, rolesAndPermissions)
	assert.Len(t, rolesAndPermissions, 1)
	assert.NotEmpty(t, rolesAndPermissions[0].Roles)
	assert.Len(t, rolesAndPermissions[0].Roles.Permissions, 2)
	assert.Equal(t, role.Name, rolesAndPermissions[0].Roles.Name)
	assert.Equal(t, role.Description, rolesAndPermissions[0].Roles.Description)
	assert.Equal(t, role.CreatedAt, rolesAndPermissions[0].Roles.CreatedAt)
	assert.Equal(t, role.CreatedBy, rolesAndPermissions[0].Roles.CreatedBy)
	assert.Equal(t, role.UpdatedAt, rolesAndPermissions[0].Roles.UpdatedAt)
	assert.Equal(t, role.UpdatedBy, rolesAndPermissions[0].Roles.UpdatedBy)

	assert.Contains(t, rolesAndPermissions[0].Roles.Permissions, permissionRes1)
	assert.Contains(t, rolesAndPermissions[0].Roles.Permissions, permissionRes2)
}

func TestServer_AssignRolesToUser_OK(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Role
	role := createRole(t, loginRes, api.CreateRole{
		Description: "role description",
		Name:        "admin_role",
	})
	//Create a new Permission
	permissionRes := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission",
	})
	//Assign Permission to Role
	assignPermissionToRole(t, permissionRes, role, loginRes)
	//Assign Roles to User
	assignRolesToUser(t, role, loginRes)
}

func TestServer_AssignRolesToUser_NOK_RolesDoesntExist(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Role
	role := createRole(t, loginRes, api.CreateRole{
		Description: "role description",
		Name:        "admin_role",
	})
	//Create a new Permission
	permissionRes := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission",
	})
	//Assign Permission to Role
	assignPermissionToRole(t, permissionRes, role, loginRes)
	//Assign Roles to User
	dbConnection := db.Connect(dbConfig)
	userQuery := usersRepo.New(dbConnection)
	user, err := userQuery.GetEntireUserByEmail(context.Background(), "first.last@example.com")
	dbConnection.Close()
	assert.NoError(t, err)
	assert.NotEmpty(t, user)
	assert.Empty(t, user.RoleNames)
	assert.Empty(t, user.PermissionNames)
	assignPermission, err := json.Marshal(api.AssignRoleToUser{
		Roles: []openapi_types.UUID{uuid.New()},
	})
	assert.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/users/%s/roles", user.UserID.String()), bytes.NewReader(assignPermission))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
}

func TestServer_RemoveRolesForUser_OK(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Role
	role := createRole(t, loginRes, api.CreateRole{
		Description: "role description",
		Name:        "admin_role",
	})
	//Create a new Permission
	permissionRes := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission",
	})
	//Assign Permission to Role
	assignPermissionToRole(t, permissionRes, role, loginRes)
	//Assign Roles to User
	assignRolesToUser(t, role, loginRes)
	//Remove Roles to User
	removeRolesFromUser(t, role, loginRes)
}

func TestServer_GetRolesOfUser_OK(t *testing.T) {
	truncateTables()
	//Signup
	signup2FADisabled(t)
	//Login
	loginRes := login2FADisabled(t)
	//Create a new Role
	role := createRole(t, loginRes, api.CreateRole{
		Description: "role description",
		Name:        "admin_role",
	})
	//Create a new Permission
	permissionRes := createPermission(t, loginRes, api.CreatePermission{
		Description: "permission description",
		Name:        "admin_permission",
	})
	//Assign Permission to Role
	assignPermissionToRole(t, permissionRes, role, loginRes)
	//Assign Roles to User
	assignRolesToUser(t, role, loginRes)
	//Get Roles of User
	dbConnection := db.Connect(dbConfig)
	userQuery := usersRepo.New(dbConnection)
	user, err := userQuery.GetEntireUserByEmail(context.Background(), "first.last@example.com")
	dbConnection.Close()
	assert.NoError(t, err)
	assert.NotEmpty(t, user)
	assert.NotEmpty(t, user.RoleNames)
	assert.Empty(t, user.PermissionNames)
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/users/%s/roles", user.UserID.String()), nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
	var userWithRoles api.UserWithRoles
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &userWithRoles))
	assert.NotEmpty(t, userWithRoles)
	assert.NotEmpty(t, userWithRoles.Roles)
	assert.Empty(t, userWithRoles.Permissions)
	id, err := util.PgtypeUUIDToUUID(user.UserID)
	require.NoError(t, err)
	assert.Equal(t, id, userWithRoles.Id)
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

func createRole(t *testing.T, res api.LoginSuccessWithJWT, req api.CreateRole) api.RoleResponse {
	createRoleRequest, err := json.Marshal(req)
	assert.NoError(t, err)

	request, err := http.NewRequest(http.MethodPost, "/api/v1/access-control/roles", bytes.NewReader(createRoleRequest))
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
	assert.Equal(t, req.Description, roleResponse.Description)
	assert.Equal(t, req.Name, roleResponse.Name)
	assert.IsType(t, uuid.UUID{}, roleResponse.Id)
	assert.Equal(t, "first.last@example.com", roleResponse.CreatedBy)
	assert.NotNil(t, roleResponse.CreatedAt)

	return roleResponse
}

func getRoleById(t *testing.T, loginRes api.LoginSuccessWithJWT, roleRes api.RoleResponse) api.RoleResponse {
	request, err := http.NewRequest(http.MethodGet, "/api/v1/access-control/roles/"+roleRes.Id.String(), nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())

	var roleResponse api.RoleResponse
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &roleResponse))
	assert.Equal(t, roleRes.Name, roleResponse.Name)
	assert.Equal(t, roleRes.Description, roleResponse.Description)
	assert.Equal(t, roleRes.CreatedAt, roleResponse.CreatedAt)
	assert.Equal(t, roleRes.CreatedBy, roleResponse.CreatedBy)
	assert.Equal(t, roleRes.UpdatedAt, roleResponse.UpdatedAt)
	assert.Equal(t, roleRes.UpdatedBy, roleResponse.UpdatedBy)

	return roleResponse
}

func getRoleByIdNotFound(t *testing.T, loginRes api.LoginSuccessWithJWT, id string) {
	request, err := http.NewRequest(http.MethodGet, "/api/v1/access-control/roles/"+id, nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusNotFound, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
}

func createPermission(t *testing.T, res api.LoginSuccessWithJWT, req api.CreatePermission) api.PermissionResponse {
	createPermissionRequest, err := json.Marshal(req)
	assert.NoError(t, err)

	request, err := http.NewRequest(http.MethodPost, "/api/v1/access-control/permissions", bytes.NewReader(createPermissionRequest))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+res.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusCreated, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())

	var permissionResponse api.PermissionResponse
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &permissionResponse))
	assert.Equal(t, req.Description, permissionResponse.Description)
	assert.Equal(t, req.Name, permissionResponse.Name)
	assert.IsType(t, uuid.UUID{}, permissionResponse.Id)
	assert.Equal(t, "first.last@example.com", permissionResponse.CreatedBy)
	assert.NotNil(t, permissionResponse.CreatedAt)

	return permissionResponse
}

func getPermissionById(t *testing.T, loginRes api.LoginSuccessWithJWT, permissionRes api.PermissionResponse) {
	request, err := http.NewRequest(http.MethodGet, "/api/v1/access-control/permissions/"+permissionRes.Id.String(), nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())

	var permissionResponse api.PermissionResponse
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &permissionResponse))
	assert.Equal(t, permissionRes.Name, permissionResponse.Name)
	assert.Equal(t, permissionRes.Description, permissionResponse.Description)
	assert.Equal(t, permissionRes.CreatedAt, permissionResponse.CreatedAt)
	assert.Equal(t, permissionRes.CreatedBy, permissionResponse.CreatedBy)
	assert.Equal(t, permissionRes.UpdatedAt, permissionResponse.UpdatedAt)
	assert.Equal(t, permissionRes.UpdatedBy, permissionResponse.UpdatedBy)
}

func getPermissionByIdNotFound(t *testing.T, loginRes api.LoginSuccessWithJWT, id string) {
	request, err := http.NewRequest(http.MethodGet, "/api/v1/access-control/permissions/"+id, nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusNotFound, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
}

func deleteRoleById(t *testing.T, loginRes api.LoginSuccessWithJWT, id string) {
	request, err := http.NewRequest(http.MethodDelete, "/api/v1/access-control/roles/"+id, nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}

func deletePermissionByIdOK(t *testing.T, loginRes api.LoginSuccessWithJWT, id string) {
	request, err := http.NewRequest(http.MethodDelete, "/api/v1/access-control/permissions/"+id, nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}

func assignPermissionToRole(t *testing.T, permissionRes api.PermissionResponse, role api.RoleResponse, loginRes api.LoginSuccessWithJWT) {
	assignPermission, err := json.Marshal(api.AssignPermission{
		Ids: []openapi_types.UUID{permissionRes.Id},
	})
	assert.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/access-control/roles/%s/permissions", role.Id.String()), bytes.NewReader(assignPermission))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}

func unassignPermissionToRole(t *testing.T, permissionRes api.PermissionResponse, role api.RoleResponse, loginRes api.LoginSuccessWithJWT) {
	request, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/access-control/roles/%s/permissions/%s", role.Id.String(), permissionRes.Id.String()), nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}

func assignRolesToUser(t *testing.T, role api.RoleResponse, loginRes api.LoginSuccessWithJWT) {
	dbConnection := db.Connect(dbConfig)
	userQuery := usersRepo.New(dbConnection)
	user, err := userQuery.GetEntireUserByEmail(context.Background(), "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, user)
	assert.Empty(t, user.RoleNames)
	assert.Empty(t, user.PermissionNames)
	assignPermission, err := json.Marshal(api.AssignRoleToUser{
		Roles: []openapi_types.UUID{role.Id},
	})
	assert.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/users/%s/roles", user.UserID.String()), bytes.NewReader(assignPermission))
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Empty(t, recorder.Body.String())
	user, err = userQuery.GetEntireUserByEmail(context.Background(), "first.last@example.com")
	dbConnection.Close()
	assert.NoError(t, err)
	assert.NotEmpty(t, user)
	assert.NotEmpty(t, user.RoleNames)
	assert.Empty(t, user.PermissionNames)
}

func removeRolesFromUser(t *testing.T, role api.RoleResponse, loginRes api.LoginSuccessWithJWT) {
	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	userQuery := usersRepo.New(dbConnection)
	user, err := userQuery.GetEntireUserByEmail(context.Background(), "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, user)
	assert.NotEmpty(t, user.RoleNames)
	assert.Empty(t, user.PermissionNames)
	assert.NoError(t, err)
	request, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/users/%s/roles/%s", user.UserID.String(), role.Id.String()), nil)
	assert.NotNil(t, request)
	assert.NoError(t, err)
	request.Header.Set("User-Agent", "api-test")
	request.Header.Set("Authorization", "Bearer "+loginRes.AccessToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Empty(t, recorder.Body.String())
	user, err = userQuery.GetEntireUserByEmail(context.Background(), "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, user)
	assert.Empty(t, user.RoleNames)
	assert.Empty(t, user.PermissionNames)
}
