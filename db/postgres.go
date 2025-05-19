package db

import (
	"errors"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/rs/zerolog/log"
)

func RunMigrationQueries(postgresqlClient *Database, migrationFolder string) {
	driver, err := postgres.WithInstance(postgresqlClient.DB, &postgres.Config{})
	if err != nil {
		log.Fatal().Err(err).Msg("Could not start SQL driver")
	}
	//Database Migration
	migration, err := migrate.NewWithDatabaseInstance("file://"+migrationFolder, "postgres", driver)
	if err != nil {
		log.Fatal().Err(err).Msg("Could not start migration")
	}
	if err = migration.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Fatal().Err(err).Msg("Migration UP failed")
	}
	log.Info().Msg("Migration UP is completed")
}
