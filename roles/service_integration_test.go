package roles

import (
	"database/sql"
	"log"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/config"
	"github.com/spdeepak/go-jwt-server/db"
	"github.com/spdeepak/go-jwt-server/roles/repository"
)

var roleStorage Storage
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
            roles
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
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, request)
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
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, request)
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
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, request)
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
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, request)
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
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, request)
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
		createdRole, err := roleService.CreateNewRole(ctx, api.CreateNewRoleParams{}, request)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdRole)
		updatedRoleDescription := "changed role description"
		updatedName := "updated_role_name"
		role, err := roleService.UpdateRoleById(ctx, createdRole.Id, api.UpdateRoleByIdParams{}, api.UpdateRole{Description: &updatedRoleDescription, Name: &updatedName})
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
		role, err := roleService.UpdateRoleById(ctx, uuid.New(), api.UpdateRoleByIdParams{}, api.UpdateRole{Description: &updatedRoleDescription, Name: &updatedName})
		assert.Error(t, err)
		assert.Empty(t, role)
	})
}
