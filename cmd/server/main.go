package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/config"
	"github.com/spdeepak/go-jwt-server/internal/db"
	"github.com/spdeepak/go-jwt-server/internal/jwt_secret"
	jwt_secretRepo "github.com/spdeepak/go-jwt-server/internal/jwt_secret/repository"
	"github.com/spdeepak/go-jwt-server/internal/logging"
	"github.com/spdeepak/go-jwt-server/internal/permissions"
	permissionsRepo "github.com/spdeepak/go-jwt-server/internal/permissions/repository"
	"github.com/spdeepak/go-jwt-server/internal/roles"
	roleRepo "github.com/spdeepak/go-jwt-server/internal/roles/repository"
	"github.com/spdeepak/go-jwt-server/internal/tokens"
	tokenRepo "github.com/spdeepak/go-jwt-server/internal/tokens/repository"
	"github.com/spdeepak/go-jwt-server/internal/twoFA"
	twoFARepo "github.com/spdeepak/go-jwt-server/internal/twoFA/repository"
	"github.com/spdeepak/go-jwt-server/internal/users"
	userRepo "github.com/spdeepak/go-jwt-server/internal/users/repository"
	"github.com/spdeepak/go-jwt-server/middleware"
)

func main() {
	slog.SetDefault(slog.New(logging.NewDefaultHandler()))
	cfg := config.NewConfiguration()

	err := db.RunMigrations(cfg.Postgres)
	if err != nil {
		slog.Error("Failed to run migrations", slog.Any("error", err))
	}
	dbConnection := db.Connect(cfg.Postgres)

	//JWT SecretKey
	jwtSecretRepository := jwt_secretRepo.New(dbConnection)
	jwtSecretStorage := jwt_secret.NewStorage(jwtSecretRepository)
	//JWT Token
	tokenRepository := tokenRepo.New(dbConnection)
	tokenStorage := tokens.NewStorage(tokenRepository)
	tokenService := tokens.NewService(tokenStorage, jwt_secret.GetOrCreateSecret(cfg.Token, jwtSecretStorage))
	//2FA
	twoFAQuery := twoFARepo.New(dbConnection)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFAService := twoFA.NewService("go-jwt-server", twoFAStorage)
	//Users
	userRepository := userRepo.New(dbConnection)
	userService := users.NewService(userRepository, twoFAService, tokenService)
	//Roles
	roleQuery := roleRepo.New(dbConnection)
	roleService := roles.NewService(roleQuery)
	//Permissions
	permissionQuery := permissionsRepo.New(dbConnection)
	permissionsService := permissions.NewService(permissionQuery)

	//oapi-codegen implementation handler
	server := NewServer(userService, roleService, permissionsService, tokenService, twoFAService)

	swagger, err := api.GetSwagger()
	if err != nil {
		slog.Error(fmt.Sprintf("Error loading swagger spec\n: %v", os.Stderr), slog.Any("error", err))
		os.Exit(1)
	}
	swagger.Servers = nil

	authMiddleware := middleware.JWTAuthMiddleware(jwt_secret.GetOrCreateSecret(cfg.Token, jwtSecretStorage), cfg.Auth.SkipPaths)
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(middleware.RequestValidator(swagger))
	router.Use(authMiddleware)
	router.Use(gin.Recovery())
	router.Use(middleware.ErrorMiddleware)
	router.Use(middleware.GinLogger())
	api.RegisterHandlers(router, server)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", 8080),
		Handler: router,
	}

	//go func() {
	//	r := mux.NewRouter()
	//	r.Path("/metrics").Handler(promhttp.Handler())
	//slog.Info(fmt.Sprintf("Starting server on %s", srv.Addr))
	//	if err = srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
	//slog.Error(fmt.Sprintf("failed to start server. Error: %s", err))
	//os.Exit(1)
	//	}
	//}()

	chanErrors := make(chan error)
	// Initializing the Server in a goroutine so that it won't block the graceful shutdown handling below
	go func() {
		chanErrors <- router.Run()
	}()

	chanSignals := make(chan os.Signal, 1)
	signal.Notify(chanSignals, os.Interrupt, syscall.SIGTERM)

	select {
	case err = <-chanErrors:
		slog.Error(fmt.Sprintf("Unable to run server. Error: %s", err))
		os.Exit(1)
	case s := <-chanSignals:
		slog.Warn(fmt.Sprintf("Warning: Received %s signal, aborting in 5 seconds...", s))
		// The context is used to inform the Server it has 5 seconds to finish the request it is currently handling
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		dbConnection.Close()
		if err = srv.Shutdown(ctx); err != nil {
			slog.Error(fmt.Sprintf("Server forced to shutdown. Error: %s", err))
			os.Exit(1)
		}
		slog.Info("Server exiting gracefully")
	}
}
