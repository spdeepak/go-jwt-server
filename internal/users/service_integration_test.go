package users

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

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
	usersRepo "github.com/spdeepak/go-jwt-server/internal/users/repository"
)

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
	MaxOpenConns:      4,
	MaxIdleConns:      4,
	ConnMaxLifetime:   10 * time.Minute,
	ConnMaxIdleTime:   2 * time.Minute,
	HealthCheckPeriod: 1 * time.Minute,
}

func TestMain(m *testing.M) {
	dbConnection := db.Connect(dbConfig)
	// Run all tests
	truncateTables()
	code := m.Run()
	// Optional: Clean up (e.g., drop DB or close connection)
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

func TestIntegrationService_Signup_No2FA(t *testing.T) {
	truncateTables()
	t.Run("Create New User without 2FA", func(t *testing.T) {
		signup_No2fa_OK(t)
	})
	t.Run("Create User already exists without 2FA", func(t *testing.T) {
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
	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	userStorage := usersRepo.New(dbConnection)
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

	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	userStorage := usersRepo.New(dbConnection)
	userService := NewService(userStorage, nil, nil)

	res, err := userService.Signup(ctx, user)
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.UserAlreadyExists, he.ErrorCode)
	assert.Empty(t, res)
}

func TestIntegrationService_Signup_2FA(t *testing.T) {
	truncateTables()
	t.Run("Create New User with 2FA", func(t *testing.T) {
		signup_2FA_OK(t)
	})
	t.Run("Create User already exists with 2FA", func(t *testing.T) {
		signup_2FA_NOK_UserAlreadyExists(t)
	})
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
	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	userStorage := usersRepo.New(dbConnection)
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
	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	userStorage := usersRepo.New(dbConnection)
	userService := NewService(userStorage, twoFaService, nil)

	res, err := userService.Signup(ctx, user)
	assert.Error(t, err)
	var he httperror.HttpError
	assert.True(t, errors.As(err, &he))
	assert.Equal(t, httperror.UserAlreadyExists, he.ErrorCode)
	assert.Empty(t, res)
}

func TestIntegrationService_Login_OK(t *testing.T) {
	truncateTables()
	t.Run("Login without 2FA", func(t *testing.T) {
		signup_No2fa_OK(t)
		login_OK(t)
	})
	t.Run("Login with 2FA invalid password", func(t *testing.T) {
		login_NOK_WrongPassword(t)
	})
	truncateTables()
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

	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	tokenQuery := tokenRepo.New(dbConnection)
	tokenService := tokens.NewService(tokenQuery, []byte("JWT_$€Cr€t"), "")
	userStorage := usersRepo.New(dbConnection)
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

	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	userStorage := usersRepo.New(dbConnection)
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

	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	userStorage := usersRepo.New(dbConnection)
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
	truncateTables()
	t.Run("Login with 2FA", func(t *testing.T) {
		login2FA_OK(t)
	})
	truncateTables()
	t.Run("Login with expired 2FA", func(t *testing.T) {
		login2FA_NOK_Old2FACode(t)
	})
	truncateTables()
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
	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	tokenQuery := tokenRepo.New(dbConnection)
	tokenService := tokens.NewService(tokenQuery, []byte(secret), "")
	twoFAQuery := twoFARepo.New(dbConnection)
	twoFaService := twoFA.NewService("go-jwt-server", twoFAQuery)
	userStorage := usersRepo.New(dbConnection)
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

	userByEmail, err := userStorage.GetEntireUserByEmail(context.Background(), "first.last@example.com")
	assert.NoError(t, err)

	passcode, err := totp.GenerateCode(res.Secret, time.Now().Add(-20*time.Second))
	assert.NoError(t, err)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userByEmail.UserID.Bytes, passcode)
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
	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	tokenQuery := tokenRepo.New(dbConnection)
	tokenService := tokens.NewService(tokenQuery, []byte(secret), "")
	twoFAQuery := twoFARepo.New(dbConnection)
	twoFaService := twoFA.NewService("go-jwt-server", twoFAQuery)
	userStorage := usersRepo.New(dbConnection)
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

	userByEmail, err := userStorage.GetEntireUserByEmail(context.Background(), "first.last@example.com")
	assert.NoError(t, err)

	passcode, err := totp.GenerateCode(res.Secret, time.Now().Add(-60*time.Second))
	assert.NoError(t, err)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, userByEmail.UserID.Bytes, passcode)
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
	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	tokenQuery := tokenRepo.New(dbConnection)
	tokenService := tokens.NewService(tokenQuery, []byte(secret), "")
	twoFAQuery := twoFARepo.New(dbConnection)
	twoFaService := twoFA.NewService("go-jwt-server", twoFAQuery)
	userStorage := usersRepo.New(dbConnection)
	userService := NewService(userStorage, twoFaService, tokenService)

	login2FA, err := userService.Login2FA(ctx, api.Login2FAParams{}, uuid.New(), "123456")
	assert.Error(t, err)
	assert.Empty(t, login2FA)
}

func TestService_GetUserRolesAndPermissions(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Set("User-Email", "first.last@example.com")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	request := api.CreateRole{
		Description: "role description",
		Name:        "role_name",
	}
	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	roleStorage := roleRepo.New(dbConnection)
	roleService := roles.NewService(roleStorage)
	permissionStorage := permissionsRepo.New(dbConnection)
	permissionsService := permissions.NewService(permissionStorage)
	roleIds := make([]uuid.UUID, 10)
	permissionIds := make([]uuid.UUID, 50)
	for num := range 10 {
		request.Name = fmt.Sprintf("%s_%d", request.Name, num)
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, "", request)
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
	assert.Len(t, rolesAndPermissions, 10)
	for _, rolesAndPermission := range rolesAndPermissions {
		assert.NotEmpty(t, rolesAndPermission)
		assert.Len(t, rolesAndPermission.Roles.Permissions, 5)
	}

	secret := "JWT_$€CR€T"
	tokenQuery := tokenRepo.New(dbConnection)
	tokenService := tokens.NewService(tokenQuery, []byte(secret), "")
	twoFAQuery := twoFARepo.New(dbConnection)
	twoFaService := twoFA.NewService("go-jwt-server", twoFAQuery)
	userStorage := usersRepo.New(dbConnection)
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

	userByEmail, err := userStorage.GetEntireUserByEmail(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, userByEmail)

	err = userStorage.AssignRolesToUser(ctx, usersRepo.AssignRolesToUserParams{
		UserID:    userByEmail.UserID,
		RoleID:    []pgtype.UUID{{Bytes: roleIds[0], Valid: true}, {Bytes: roleIds[1], Valid: true}, {Bytes: roleIds[2], Valid: true}},
		CreatedBy: "first.last@example.com",
	})
	assert.NoError(t, err)
	err = userStorage.AssignPermissionToUser(ctx, usersRepo.AssignPermissionToUserParams{
		UserID:       userByEmail.UserID,
		PermissionID: []pgtype.UUID{{Bytes: permissionIds[10], Valid: true}, {Bytes: permissionIds[11], Valid: true}, {Bytes: permissionIds[12], Valid: true}, {Bytes: permissionIds[13], Valid: true}},
		CreatedBy:    "first.last@example.com",
	})
	assert.NoError(t, err)

	userRolesAndPermissions, err := userService.GetUserRolesAndPermissions(ctx, userByEmail.UserID.Bytes, api.GetRolesOfUserParams{})
	assert.NoError(t, err)
	assert.NotEmpty(t, userRolesAndPermissions)
	assert.Len(t, userRolesAndPermissions.Roles, 3)
	assert.Len(t, userRolesAndPermissions.Permissions, 4)

	truncateTables()
}

func TestService_AssignRolesToUser(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Set("User-Email", "first.last@example.com")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	request := api.CreateRole{
		Description: "role description",
		Name:        "role_name",
	}
	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	roleStorage := roleRepo.New(dbConnection)
	roleService := roles.NewService(roleStorage)
	createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, "", request)
	assert.NoError(t, err)
	assert.NotEmpty(t, createdRole)

	rolesAndPermissions, err := roleService.ListRolesAndItsPermissions(ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, rolesAndPermissions)
	assert.Len(t, rolesAndPermissions, 1)
	for _, rolesAndPermission := range rolesAndPermissions {
		assert.NotEmpty(t, rolesAndPermission)
		assert.Len(t, rolesAndPermission.Roles.Permissions, 0)
	}

	secret := "JWT_$€CR€T"
	tokenQuery := tokenRepo.New(dbConnection)
	tokenService := tokens.NewService(tokenQuery, []byte(secret), "")
	twoFAQuery := twoFARepo.New(dbConnection)
	twoFaService := twoFA.NewService("go-jwt-server", twoFAQuery)
	userStorage := usersRepo.New(dbConnection)
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

	userByEmail, err := userStorage.GetEntireUserByEmail(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, userByEmail)

	err = userService.AssignRolesToUser(ctx, userByEmail.UserID.Bytes, api.AssignRolesToUserParams{}, api.AssignRoleToUser{Roles: []uuid.UUID{createdRole.Id}}, "first.last@example.com")
	assert.NoError(t, err)

	truncateTables()
}

func TestService_UnassignRolesToUser(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Header("x-login-source", "test")
	ctx.Set("User-Email", "first.last@example.com")
	ctx.Header("user-agent", "test")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	ctx.Request = req

	request := api.CreateRole{
		Description: "role description",
		Name:        "role_name",
	}
	dbConnection := db.Connect(dbConfig)
	defer dbConnection.Close()
	roleStorage := roleRepo.New(dbConnection)
	roleService := roles.NewService(roleStorage)
	createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, "", request)
	assert.NoError(t, err)
	assert.NotEmpty(t, createdRole)

	rolesAndPermissions, err := roleService.ListRolesAndItsPermissions(ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, rolesAndPermissions)
	assert.Len(t, rolesAndPermissions, 1)
	for _, rolesAndPermission := range rolesAndPermissions {
		assert.NotEmpty(t, rolesAndPermission)
		assert.Len(t, rolesAndPermission.Roles.Permissions, 0)
	}

	secret := "JWT_$€CR€T"
	tokenQuery := tokenRepo.New(dbConnection)
	tokenService := tokens.NewService(tokenQuery, []byte(secret), "")
	twoFAQuery := twoFARepo.New(dbConnection)
	twoFaService := twoFA.NewService("go-jwt-server", twoFAQuery)
	userStorage := usersRepo.New(dbConnection)
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

	userByEmail, err := userStorage.GetEntireUserByEmail(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, userByEmail)

	err = userService.AssignRolesToUser(ctx, userByEmail.UserID.Bytes, api.AssignRolesToUserParams{}, api.AssignRoleToUser{Roles: []uuid.UUID{createdRole.Id}}, "first.last@example.com")
	assert.NoError(t, err)

	userRolesAndPermissions, err := userService.GetUserRolesAndPermissions(ctx, userByEmail.UserID.Bytes, api.GetRolesOfUserParams{})
	assert.NoError(t, err)
	assert.NotEmpty(t, userRolesAndPermissions)
	assert.NotEmpty(t, userRolesAndPermissions.Roles)
	assert.Len(t, userRolesAndPermissions.Roles, 1)

	err = userService.UnassignRolesOfUser(ctx, userByEmail.UserID.Bytes, createdRole.Id, api.RemoveRolesForUserParams{})
	assert.NoError(t, err)

	userByEmail, err = userStorage.GetEntireUserByEmail(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, userByEmail)
	assert.Empty(t, userByEmail.RoleNames)

	truncateTables()
}
