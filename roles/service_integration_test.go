package roles

import (
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
	"github.com/stretchr/testify/assert"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/config"
	"github.com/spdeepak/go-jwt-server/db"
	"github.com/spdeepak/go-jwt-server/permissions"
	permissionsRepo "github.com/spdeepak/go-jwt-server/permissions/repository"
	"github.com/spdeepak/go-jwt-server/roles/repository"
)

var roleStorage Storage
var permissionStorage permissions.Storage
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
	roleStorage = NewStorage(query)
	permissionQuery := permissionsRepo.New(dbConnection.DB)
	permissionStorage = permissions.NewStorage(permissionQuery)
	// Run all tests
	_, err = dba.DB.Exec(`
        TRUNCATE TABLE
            users_2fa,
            users_password,
            users,
            tokens,
            roles,
            permissions,
            role_permissions
        RESTART IDENTITY CASCADE
    `)
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
            role_permissions
        RESTART IDENTITY CASCADE
    `)
	assert.NoError(t, err)
}

func TestService_CreateNewRole(t *testing.T) {
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
	truncateTables(t, dba.DB)
}

func TestService_DeleteRole(t *testing.T) {
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
	truncateTables(t, dba.DB)
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
	truncateTables(t, dba.DB)
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
	truncateTables(t, dba.DB)
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
	truncateTables(t, dba.DB)
}

func TestService_UnassignPermissionToRole(t *testing.T) {
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
	truncateTables(t, dba.DB)
}

func TestService_ListRolesAndItsPermissions(t *testing.T) {
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
	truncateTables(t, dba.DB)
}
