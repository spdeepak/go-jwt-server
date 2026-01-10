package roles

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/config"
	"github.com/spdeepak/go-jwt-server/internal/db"
	"github.com/spdeepak/go-jwt-server/internal/permissions"
	permissionsRepo "github.com/spdeepak/go-jwt-server/internal/permissions/repository"
	roleRepo "github.com/spdeepak/go-jwt-server/internal/roles/repository"
)

var roleStorage roleRepo.Querier
var permissionStorage permissionsRepo.Querier
var dba *pgxpool.Pool

func TestMain(m *testing.M) {
	t := &testing.T{}
	dbConfig := config.PostgresConfig{
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
	dbConnection := db.Connect(dbConfig)
	dba = dbConnection
	require.NoError(t, resetPublicSchema(dba))
	require.NoError(t, db.RunMigrations(dbConfig))
	roleStorage = roleRepo.New(dbConnection)
	permissionStorage = permissionsRepo.New(dbConnection)
	// Run all tests
	truncateTables(t, dba)
	code := m.Run()
	// Optional: Clean up (e.g., drop DB or close connection)
	require.NoError(t, resetPublicSchema(dba))
	dbConnection.Close()
	os.Exit(code)
}

func truncateTables(t *testing.T, db *pgxpool.Pool) {
	_, err := db.Exec(context.Background(), `
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

func resetPublicSchema(pool *pgxpool.Pool) error {
	_, err := pool.Exec(context.Background(), `
        DROP SCHEMA IF EXISTS public CASCADE;
        CREATE SCHEMA public;
    `)
	return err
}

func TestService_CreateNewRole(t *testing.T) {
	truncateTables(t, dba)
	t.Run("Create New Role OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreateRole{
			Description: "role description",
			Name:        "role_name",
		}
		roleService := NewService(roleStorage)
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, "first.last@example.com", request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdRole)
	})
	t.Run("Create New Role NOK duplicate", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreateRole{
			Description: "role description",
			Name:        "role_name",
		}
		roleService := NewService(roleStorage)
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, "first.last@example.com", request)
		assert.Error(t, err)
		assert.Empty(t, createdRole)
	})
}

func TestService_DeleteRole(t *testing.T) {
	truncateTables(t, dba)
	t.Run("Delete Role OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreateRole{
			Description: "role description",
			Name:        "role_name",
		}
		roleService := NewService(roleStorage)
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, "first.last@example.com", request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdRole)
		err = roleService.DeleteRoleById(ctx, createdRole.Id)
		assert.NoError(t, err)
	})
	t.Run("Delete Role OK not exists", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		roleService := NewService(roleStorage)
		err := roleService.DeleteRoleById(ctx, uuid.New())
		assert.NoError(t, err)
	})
}

func TestService_ListRoles(t *testing.T) {
	truncateTables(t, dba)
	t.Run("List Roles OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreateRole{
			Description: "role description",
			Name:        "role_name",
		}
		roleService := NewService(roleStorage)
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, "first.last@example.com", request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdRole)
		roles, err := roleService.ListRoles(ctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, roles)
		assert.Equal(t, request.Name, roles[0].Name)
		assert.Equal(t, request.Description, roles[0].Description)
	})
	truncateTables(t, dba)
	t.Run("List Roles Empty", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		roleService := NewService(roleStorage)
		createdRole, err := roleService.ListRoles(ctx)
		assert.NoError(t, err)
		assert.Empty(t, createdRole)
	})
}

func TestService_GetRoleById(t *testing.T) {
	truncateTables(t, dba)
	t.Run("Get Role by ID OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreateRole{
			Description: "role description",
			Name:        "role_name",
		}
		roleService := NewService(roleStorage)
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, "first.last@example.com", request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdRole)
		role, err := roleService.GetRoleById(ctx, createdRole.Id)
		assert.NoError(t, err)
		assert.NotEmpty(t, role)
		assert.Equal(t, request.Name, role.Name)
		assert.Equal(t, request.Description, role.Description)
	})
	truncateTables(t, dba)
	t.Run("Get Role by ID NOK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		roleService := NewService(roleStorage)
		role, err := roleService.GetRoleById(ctx, uuid.New())
		assert.Error(t, err)
		assert.Empty(t, role)
	})
}

func TestService_UpdateRoleById(t *testing.T) {
	truncateTables(t, dba)
	t.Run("Get Role by ID OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreateRole{
			Description: "role description",
			Name:        "role_name",
		}
		roleService := NewService(roleStorage)
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, "first.last@example.com", request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdRole)
		updatedRoleDescription := "changed role description"
		updatedName := "updated_role_name"
		role, err := roleService.UpdateRoleById(ctx, createdRole.Id, "first.last@example.com", api.UpdateRoleByIdParams{}, api.UpdateRole{Description: &updatedRoleDescription, Name: &updatedName})
		assert.NoError(t, err)
		assert.NotEmpty(t, role)
		assert.Equal(t, updatedRoleDescription, role.Description)
		assert.Equal(t, updatedName, role.Name)
		assert.Equal(t, role.CreatedAt, createdRole.CreatedAt)
		assert.NotEqual(t, role.UpdatedAt, createdRole.UpdatedAt)
	})
	truncateTables(t, dba)
	t.Run("Get Role by ID NOK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		roleService := NewService(roleStorage)

		updatedRoleDescription := "changed role description"
		updatedName := "updated_role_name"
		role, err := roleService.UpdateRoleById(ctx, uuid.New(), "first.last@example.com", api.UpdateRoleByIdParams{}, api.UpdateRole{Description: &updatedRoleDescription, Name: &updatedName})
		assert.Error(t, err)
		assert.Empty(t, role)
	})
}

func TestService_AssignPermissionToRole(t *testing.T) {
	truncateTables(t, dba)
	t.Run("Assign Permission to Role OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreateRole{
			Description: "role description",
			Name:        "role_name",
		}
		roleService := NewService(roleStorage)
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, "first.last@example.com", request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdRole)
		permissionsService := permissions.NewService(permissionStorage)
		permission, err := permissionsService.CreateNewPermission(ctx, api.CreateNewPermissionParams{}, api.CreatePermission{Description: "permission description", Name: "role::create"})
		assert.NoError(t, err)
		assert.NotEmpty(t, permission)

		err = roleService.AssignPermissionToRole(ctx, createdRole.Id, api.AssignPermissionToRoleParams{}, api.AssignPermission{Ids: []openapi_types.UUID{permission.Id}}, "first.last@example.com")
		assert.NoError(t, err)
	})
}

func TestService_UnassignPermissionToRole(t *testing.T) {
	truncateTables(t, dba)
	t.Run("Assign Permission to Role OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreateRole{
			Description: "role description",
			Name:        "role_name",
		}
		roleService := NewService(roleStorage)
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, "first.last@example.com", request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdRole)
		permissionsService := permissions.NewService(permissionStorage)
		permission, err := permissionsService.CreateNewPermission(ctx, api.CreateNewPermissionParams{}, api.CreatePermission{Description: "permission description", Name: "role::create"})
		assert.NoError(t, err)
		assert.NotEmpty(t, permission)

		err = roleService.AssignPermissionToRole(ctx, createdRole.Id, api.AssignPermissionToRoleParams{}, api.AssignPermission{Ids: []openapi_types.UUID{permission.Id}}, "first.last@example.com")
		assert.NoError(t, err)
		err = roleService.UnassignPermissionFromRole(ctx, createdRole.Id, permission.Id)
		assert.NoError(t, err)
	})
}

func TestService_ListRolesAndItsPermissions(t *testing.T) {
	truncateTables(t, dba)
	t.Run("List Roles And Its Permissions OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Set("X-User-Email", "first.last@example.com")
		request := api.CreateRole{
			Description: "role description",
			Name:        "role_name",
		}
		roleService := NewService(roleStorage)
		permissionsService := permissions.NewService(permissionStorage)

		for num := range 10 {
			request.Name = fmt.Sprintf("%s_%d", request.Name, num)
			createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, "first.last@example.com", request)
			assert.NoError(t, err)
			assert.NotEmpty(t, createdRole)
			for pn := range 5 {
				permission, err := permissionsService.CreateNewPermission(ctx, api.CreateNewPermissionParams{}, api.CreatePermission{Description: "permission description", Name: fmt.Sprintf("role::create_%d_%d", num, pn)})
				assert.NoError(t, err)
				assert.NotEmpty(t, permission)
				err = roleService.AssignPermissionToRole(ctx, createdRole.Id, api.AssignPermissionToRoleParams{}, api.AssignPermission{Ids: []openapi_types.UUID{permission.Id}}, "first.last@example.com")
				assert.NoError(t, err)
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
	})
}
