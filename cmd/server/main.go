package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/config"
	"github.com/spdeepak/go-jwt-server/db"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/jwt_secret"
	secret "github.com/spdeepak/go-jwt-server/jwt_secret/repository"
	"github.com/spdeepak/go-jwt-server/middleware"
	"github.com/spdeepak/go-jwt-server/tokens"
	token "github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/spdeepak/go-jwt-server/twofa"
	otp "github.com/spdeepak/go-jwt-server/twofa/repository"
	"github.com/spdeepak/go-jwt-server/users"
	user "github.com/spdeepak/go-jwt-server/users/repository"
)

func main() {

	cfg := config.NewConfiguration()

	dbConnection, err := db.Connect(cfg.Postgres)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	db.RunMigrationQueries(dbConnection, "migrations")

	//JWT SecretKey
	jwtSecretRepository := secret.New(dbConnection.DB)
	jwtSecretStorage := jwt_secret.NewStorage(jwtSecretRepository)
	//JWT Token
	tokenRepository := token.New(dbConnection.DB)
	tokenStorage := tokens.NewStorage(tokenRepository)
	tokenService := tokens.NewService(tokenStorage, jwt_secret.GetOrCreateSecret(cfg.Token, jwtSecretStorage))
	//2FA
	twoFAQuery := otp.New(dbConnection.DB)
	twoFAStorage := twoFA.NewStorage(twoFAQuery)
	twoFAService := twoFA.NewService("", twoFAStorage, tokenService)
	//Users
	userRepository := user.New(dbConnection.DB)
	userStorage := users.NewStorage(userRepository)
	userService := users.NewService(userStorage, tokenService)

	//oapi-codegen implementation handler
	server := NewServer(userService, tokenService, twoFAService)

	swagger, err := api.GetSwagger()
	if err != nil {
		log.Err(err).Msgf("Error loading swagger spec\n: %v", os.Stderr)
		os.Exit(1)
	}
	swagger.Servers = nil

	authMiddleware := middleware.JWTAuthMiddleware(jwt_secret.GetOrCreateSecret(cfg.Token, jwtSecretStorage), nil)

	router := gin.New()
	router.Use(httperror.Middleware)
	router.Use(middleware.GinLogger())
	router.Use(authMiddleware)
	api.RegisterHandlers(router, server)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", 8080),
		Handler: router,
	}

	chanErrors := make(chan error)
	// Initializing the Server in a goroutine so that it won't block the graceful shutdown handling below
	go func() {
		chanErrors <- router.Run()
	}()

	chanSignals := make(chan os.Signal, 1)
	signal.Notify(chanSignals, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-chanErrors:
		log.Fatal().Err(err).Msg("Unable to run Server")
	case s := <-chanSignals:
		log.Warn().Msgf("Warning: Received %s signal, aborting in 5 seconds...", s)
		// The context is used to inform the Server it has 5 seconds to finish the request it is currently handling
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Fatal().Err(err).Msgf("Server forced to shutdown")
		}
		log.Info().Msgf("Server exiting gracefully")
	}
}
