package users

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/config"
	"github.com/spdeepak/go-jwt-server/db"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/permissions"
	permissionsRepo "github.com/spdeepak/go-jwt-server/permissions/repository"
	"github.com/spdeepak/go-jwt-server/roles"
	roleRepo "github.com/spdeepak/go-jwt-server/roles/repository"
	"github.com/spdeepak/go-jwt-server/tokens"
	tokenRepo "github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/spdeepak/go-jwt-server/twoFA"
	twoFARepo "github.com/spdeepak/go-jwt-server/twoFA/repository"
	"github.com/spdeepak/go-jwt-server/users/repository"
)

var userStorage Storage
var roleStorage roles.Storage
var permissionStorage permissions.Storage
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
	roleQuery := roleRepo.New(dbConnection.DB)
	roleStorage = roles.NewStorage(roleQuery)
	permissionQuery := permissionsRepo.New(dbConnection.DB)
	permissionStorage = permissions.NewStorage(permissionQuery)
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
            tokens,
            roles,
            permissions,
            role_permissions,
            user_permissions
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

	userByEmail, err := userStorage.GetUserByEmailForAuth(context.Background(), "first.last@example.com")
	assert.NoError(t, err)

	passcode, err := totp.GenerateCode(res.Secret, time.Now().Add(-20*time.Second))
	assert.NoError(t, err)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userByEmail.UserID, passcode)
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

	userByEmail, err := userStorage.GetUserByEmailForAuth(context.Background(), "first.last@example.com")
	assert.NoError(t, err)

	passcode, err := totp.GenerateCode(res.Secret, time.Now().Add(-60*time.Second))
	assert.NoError(t, err)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userByEmail.UserID, passcode)
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

func TestService_GetUserRolesAndPermissions(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Set("X-User-Email", "first.last@example.com")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	request := api.CreateRole{
		Description: "role description",
		Name:        "role_name",
	}
	roleService := roles.NewService(roleStorage)
	permissionsService := permissions.NewService(permissionStorage)
	roleIds := make([]uuid.UUID, 10)
	permissionIds := make([]uuid.UUID, 50)
	for num := range 10 {
		request.Name = fmt.Sprintf("%s_%d", request.Name, num)
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdRole)
		roleIds[num] = createdRole.Id
		for pn := range 5 {
			permission, err := permissionsService.CreateNewPermission(ctx, api.CreateNewPermissionParams{}, api.CreatePermission{Description: "permission description", Name: fmt.Sprintf("role::create_%d_%d", num, pn)})
			assert.NoError(t, err)
			assert.NotEmpty(t, permission)
			err = roleService.AssignPermissionToRole(ctx, createdRole.Id, api.AssignPermissionToRoleParams{}, api.AssignPermission{Ids: []openapi_types.UUID{permission.Id}}, "first.last@example.com")
			assert.NoError(t, err)
			permissionIds[num+pn] = permission.Id
		}
	}
	rolesAndPermissions, err := roleService.ListRolesAndItsPermissions(ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, rolesAndPermissions)
	assert.Equal(t, 10, len(rolesAndPermissions))
	for _, rolesAndPermission := range rolesAndPermissions {
		assert.NotEmpty(t, rolesAndPermission)
		assert.Equal(t, 5, len(rolesAndPermission.Roles.Permissions))
	}

	secret := "JWT_$€CR€T"
	tokenService := tokens.NewService(tokenStorage, []byte(secret))
	twoFaService := twoFA.NewService("go-jwt-server", twoFAStorage)
	userService := NewService(userStorage, twoFaService, tokenService)

	user := api.UserSignup{
		Email:     "first.last@example.com",
		FirstName: "First name",
		LastName:  "Last name",
		Password:  "Som€_$trong_P@$$word",
	}

	res, err := userService.Signup(ctx, user)
	assert.NoError(t, err)
	assert.Empty(t, res)

	userByEmail, err := userStorage.GetUserByEmailForAuth(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, userByEmail)

	err = userStorage.AssignRolesToUser(ctx, repository.AssignRolesToUserParams{
		UserID:    userByEmail.UserID,
		RoleID:    []uuid.UUID{roleIds[0], roleIds[1], roleIds[2]},
		CreatedBy: "first.last@example.com",
	})
	assert.NoError(t, err)
	err = userStorage.AssignPermissionToUser(ctx, repository.AssignPermissionToUserParams{
		UserID:       userByEmail.UserID,
		PermissionID: []uuid.UUID{permissionIds[10], permissionIds[11], permissionIds[12]},
		CreatedBy:    "first.last@example.com",
	})
	assert.NoError(t, err)

	userRolesAndPermissions, err := userService.GetUserRolesAndPermissions(ctx, userByEmail.UserID, api.GetRolesOfUserParams{})
	assert.NoError(t, err)
	assert.NotEmpty(t, userRolesAndPermissions)

	truncateTables(t, dba.DB)
}
