package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/spdeepak/go-jwt-server/config"
)

type Database struct {
	DB *sql.DB
}

func Connect(config config.PostgresConfig) (*Database, error) {
	connStr := ""
	if config.Port != "" {
		connStr = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d", config.Host, config.Port, config.UserName, config.Password, config.DBName, config.SSLMode, int(config.Timeout.Seconds()))
	} else {
		connStr = fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d", config.Host, config.UserName, config.Password, config.DBName, config.SSLMode, int(config.Timeout.Seconds()))
	}

	var db *sql.DB
	var err error

	for i := 0; i < config.MaxRetry; i++ {
		db, err = sql.Open("pgx", connStr)
		if err == nil {
			err = db.Ping()
			if err == nil {
				return &Database{DB: db}, nil
			}
		}
		time.Sleep(5 * time.Second) // Wait before retrying
	}
	return nil, fmt.Errorf("could not connect to PostgreSQL after %d attempts: %w", config.MaxRetry, err)
}

func (d *Database) GracefulShutdown(graceTime time.Duration) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	_, cancel := context.WithTimeout(context.Background(), graceTime)
	defer func() {
		cancel()
		_ = d.DB.Close()
	}()
}
