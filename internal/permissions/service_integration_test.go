package permissions

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/config"
	"github.com/spdeepak/go-jwt-server/internal/db"
	"github.com/spdeepak/go-jwt-server/internal/permissions/repository"
)

var permissionStorage repository.Querier
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
	MaxOpenConns:      1,
	MaxIdleConns:      1,
	ConnMaxLifetime:   10 * time.Minute,
	ConnMaxIdleTime:   2 * time.Minute,
	HealthCheckPeriod: 1 * time.Minute,
}

func TestMain(m *testing.M) {
	dbConnection := db.Connect(dbConfig)
	permissionStorage = repository.New(dbConnection)
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
	assert.NoError(t, err)
}

func TestService_CreateNewPermission(t *testing.T) {
	t.Run("Create New Permission OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreatePermission{
			Description: "permission description",
			Name:        "permission_name",
		}
		permissionService := NewService(permissionStorage)
		createdPermission, err := permissionService.CreateNewPermission(ctx, api.CreateNewPermissionParams{}, request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdPermission)
	})
	t.Run("Create New Permission NOK duplicate", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreatePermission{
			Description: "permission description",
			Name:        "permission_name",
		}
		permissionService := NewService(permissionStorage)
		createdPermission, err := permissionService.CreateNewPermission(ctx, api.CreateNewPermissionParams{}, request)
		assert.Error(t, err)
		assert.Empty(t, createdPermission)
	})
	truncateTables()
}

func TestService_DeletePermission(t *testing.T) {
	t.Run("Delete Permission OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreatePermission{
			Description: "permission description",
			Name:        "permission_name",
		}
		permissionService := NewService(permissionStorage)
		createdPermission, err := permissionService.CreateNewPermission(ctx, api.CreateNewPermissionParams{}, request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdPermission)
		err = permissionService.DeletePermissionById(ctx, createdPermission.Id)
		assert.NoError(t, err)
	})
	t.Run("Delete Permission OK not exists", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		permissionService := NewService(permissionStorage)
		err := permissionService.DeletePermissionById(ctx, uuid.New())
		assert.NoError(t, err)
	})
}

func TestService_ListPermissions(t *testing.T) {
	t.Run("List Permissions OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreatePermission{
			Description: "permission description",
			Name:        "permission_name",
		}
		permissionService := NewService(permissionStorage)
		createdPermission, err := permissionService.CreateNewPermission(ctx, api.CreateNewPermissionParams{}, request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdPermission)
		permissions, err := permissionService.ListPermissions(ctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, permissions)
		assert.Equal(t, request.Name, permissions[0].Name)
		assert.Equal(t, request.Description, permissions[0].Description)
	})
	truncateTables()
	t.Run("List Permissions Empty", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		permissionService := NewService(permissionStorage)
		createdPermission, err := permissionService.ListPermissions(ctx)
		assert.NoError(t, err)
		assert.Empty(t, createdPermission)
	})
}

func TestService_GetPermissionById(t *testing.T) {
	t.Run("Get Permission by ID OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreatePermission{
			Description: "permission description",
			Name:        "permission_name",
		}
		permissionService := NewService(permissionStorage)
		createdPermission, err := permissionService.CreateNewPermission(ctx, api.CreateNewPermissionParams{}, request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdPermission)
		permission, err := permissionService.GetPermissionById(ctx, createdPermission.Id)
		assert.NoError(t, err)
		assert.NotEmpty(t, permission)
		assert.Equal(t, request.Name, permission.Name)
		assert.Equal(t, request.Description, permission.Description)
	})
	truncateTables()
	t.Run("Get Permission by ID NOK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		permissionService := NewService(permissionStorage)
		permission, err := permissionService.GetPermissionById(ctx, uuid.New())
		assert.Error(t, err)
		assert.Empty(t, permission)
	})
}

func TestService_UpdatePermissionById(t *testing.T) {
	t.Run("Get Permission by ID OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreatePermission{
			Description: "permission description",
			Name:        "permission_name",
		}
		permissionService := NewService(permissionStorage)
		createdPermission, err := permissionService.CreateNewPermission(ctx, api.CreateNewPermissionParams{}, request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdPermission)
		updatedPermissionDescription := "changed permission description"
		updatedName := "updated_permission_name"
		permission, err := permissionService.UpdatePermissionById(ctx, createdPermission.Id, api.UpdatePermissionByIdParams{}, api.UpdatePermission{Description: &updatedPermissionDescription, Name: &updatedName})
		assert.NoError(t, err)
		assert.NotEmpty(t, permission)
		assert.Equal(t, updatedPermissionDescription, permission.Description)
		assert.Equal(t, updatedName, permission.Name)
		assert.Equal(t, permission.CreatedAt, createdPermission.CreatedAt)
		assert.NotEqual(t, permission.UpdatedAt, createdPermission.UpdatedAt)
	})
	truncateTables()
	t.Run("Get Permission by ID NOK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		permissionService := NewService(permissionStorage)

		updatedPermissionDescription := "changed permission description"
		updatedName := "updated_permission_name"
		permission, err := permissionService.UpdatePermissionById(ctx, uuid.New(), api.UpdatePermissionByIdParams{}, api.UpdatePermission{Description: &updatedPermissionDescription, Name: &updatedName})
		assert.Error(t, err)
		assert.Empty(t, permission)
	})
}
