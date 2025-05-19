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
	"github.com/spdeepak/go-jwt-server/db"
)

func main() {

	config := db.Config{
		Host:     "localhost",
		Port:     "5432",
		UserName: "admin",
		Password: "admin",
		DBName:   "jwt_server",
		SSLMode:  "disable",
		Timeout:  10 * time.Second,
		MaxRetry: 5,
	}

	dbConnection, err := db.Connect(config)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	db.RunMigrationQueries(dbConnection, "migrations")

	//oapi-codegen implementation handler
	server := NewServer()

	swagger, err := api.GetSwagger()
	if err != nil {
		log.Err(err).Msgf("Error loading swagger spec\n: %s", os.Stderr)
		os.Exit(1)
	}
	swagger.Servers = nil

	router := gin.New()
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
