package db

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/spdeepak/go-jwt-server/config"
)

func Connect(dbCfg config.PostgresConfig) *pgxpool.Pool {
	dsn := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=%s statement_timeout=%s",
		dbCfg.Host,
		dbCfg.Port,
		dbCfg.DBName,
		dbCfg.UserName,
		dbCfg.Password,
		dbCfg.SSLMode,
		dbCfg.Timeout,
	)

	pgConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		slog.Error("error parsing connection string", "error", err)
		os.Exit(1)
		return nil
	}

	pgConfig.MaxConns = int32(dbCfg.MaxOpenConns)
	pgConfig.MinConns = int32(dbCfg.MaxIdleConns)
	pgConfig.MaxConnLifetime = dbCfg.ConnMaxLifetime
	pgConfig.MaxConnIdleTime = dbCfg.ConnMaxIdleTime

	pool, err := pgxpool.NewWithConfig(context.Background(), pgConfig)
	if err != nil {
		slog.Error("error connecting to database", "error", err)
		os.Exit(1)
		return nil
	}

	return pool
}
