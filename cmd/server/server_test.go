package main

import (
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

var twoFaService twoFA.Service
var tokenService tokens.Service
var userService users.Service
var rolesService roles.Service
var permissionService permissions.Service
var router *gin.Engine

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
	//dba := dbConnection
	db.RunMigrationQueries(dbConnection, "../../migrations")
	twoFAQuery := twoFARepo.New(dbConnection.DB)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFaService = twoFA.NewService("go-jwt-server", twoFAStorage)
	tokenQuery := tokenRepo.New(dbConnection.DB)
	tokenStorage := tokens.NewStorage(tokenQuery)
	tokenService = tokens.NewService(tokenStorage, []byte("JWT_$€Cr€t"))
	userQuery := repository.New(dbConnection.DB)
	userStorage := users.NewStorage(userQuery)
	userService = users.NewService(userStorage, twoFaService, tokenService)
	roleQuery := roleRepo.New(dbConnection.DB)
	roleStorage := roles.NewStorage(roleQuery)
	rolesService = roles.NewService(roleStorage)
	permissionQuery := permissionsRepo.New(dbConnection.DB)
	permissionStorage := permissions.NewStorage(permissionQuery)
	permissionService = permissions.NewService(permissionStorage)
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
	os.Exit(code)
}

func TestReadyEndpoint(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
