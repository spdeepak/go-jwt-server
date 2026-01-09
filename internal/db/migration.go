package db

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/spdeepak/go-jwt-server/config"
)

func RunMigrations(cfg config.PostgresConfig) error {
	// Build database URL
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.UserName,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.DBName,
		cfg.SSLMode,
	)

	// Get current directory for migrations path
	wd, _ := os.Getwd()
	migrationsPath := "file://migrations"
	slog.Info("Setting up migrations",
		"working_directory", wd,
		"migrations_path", migrationsPath,
	)

	// Create migrate instance
	slog.Info("Creating migrate instance...")
	m, err := migrate.New(migrationsPath, dbURL)
	if err != nil {
		slog.Error("Failed to create migrate instance",
			"error", err,
			"migrations_path", migrationsPath,
			"database", cfg.DBName,
		)
		return err
	}
	defer m.Close()
	slog.Info("Migrate instance created successfully")

	// Check current version
	version, dirty, err := m.Version()
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		slog.Error("Failed to get current migration version", "error", err)
		return err
	}
	if errors.Is(err, migrate.ErrNilVersion) {
		slog.Info("No migrations have been run yet")
	} else {
		slog.Info("Current migration version",
			"version", version,
			"dirty", dirty,
		)
	}

	// Run migrations up
	slog.Info("Running database migrations up...")
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			slog.Info("No new migrations to run - database is up to date")
		} else {
			slog.Error("Failed to run migrations up",
				"error", err,
				"error_type", fmt.Sprintf("%T", err),
			)
			return err
		}
	} else {
		// Get updated version after migration
		newVersion, dirty, _ := m.Version()
		slog.Info("Database migrations completed successfully",
			"new_version", newVersion,
			"dirty", dirty,
		)
	}

	return nil
}
