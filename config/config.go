package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

type AppConfig struct {
	v        *viper.Viper
	Token    Token          `required:"true" json:"token" yaml:"token"`
	Postgres PostgresConfig `required:"true" json:"postgres" yaml:"postgres"`
	Auth     Auth           `required:"true" json:"auth" yaml:"auth"`
}

type Token struct {
	Secret    string `json:"secretKey" yaml:"secret"`
	MasterKey string `json:"masterKey" yaml:"masterKey"`
	Issuer    string `required:"true" json:"issuer" yaml:"issuer"`
}

type PostgresConfig struct {
	Host              string        `required:"true" json:"host" yaml:"host"`
	Port              string        `json:"port" yaml:"port"`
	DBName            string        `required:"true" json:"dbName" yaml:"dbName"`
	UserName          string        `required:"true" json:"username" yaml:"username"`
	Password          string        `required:"true" json:"password" yaml:"password"`
	SSLMode           string        `required:"true" json:"sslMode" yaml:"sslMode"`
	Timeout           time.Duration `required:"true" json:"timeout" yaml:"timeout"`
	MaxRetry          int           `required:"true" json:"maxRetry" yaml:"maxRetry"`
	ConnectTimeout    time.Duration `required:"true" json:"connectTimeout" yaml:"connectTimeout" validate:"required,gt=0"`
	StatementTimeout  time.Duration `required:"true" json:"statementTimeout" yaml:"statementTimeout" validate:"required,gt=0"`
	MaxOpenConns      int           `required:"true" json:"maxOpenConns" yaml:"maxOpenConns" validate:"required,gt=0"`
	MaxIdleConns      int           `required:"true" json:"maxIdleConns" yaml:"maxIdleConns" validate:"required,gt=0"`
	ConnMaxLifetime   time.Duration `required:"true" json:"connMaxLifetime" yaml:"connMaxLifetime" validate:"required,gt=0"`
	ConnMaxIdleTime   time.Duration `required:"true" json:"connMaxIdleTime" yaml:"connMaxIdleTime" validate:"required,gt=0"`
	HealthCheckPeriod time.Duration `required:"true" json:"healthCheckPeriod" yaml:"healthCheckPeriod" validate:"required,gt=0"`
}

type Auth struct {
	SkipPaths []string `json:"skipPaths" yaml:"skipPaths"`
}

type Bearer struct {
	TTL time.Duration `required:"true" json:"ttl" yaml:"ttl"`
}

type Refresh struct {
	TTL time.Duration `required:"true" json:"ttl" yaml:"ttl"`
}

type secret struct {
	v        *viper.Viper
	JWT      JWT            `required:"true" json:"jwt" yaml:"jwt"`
	Postgres PostgresConfig `json:"postgres" yaml:"postgres"`
}

type JWT struct {
	SecretKey string `json:"secretKey" yaml:"secretKey"`
	MasterKey string `json:"masterKey" yaml:"masterKey"`
}

func (c *AppConfig) readAppConfig() {
	v := viper.New()

	v.SetTypeByDefaultValue(true)
	v.SetConfigFile(os.Getenv("CONFIG_FILE_PATH"))
	c.v = v

	if err := v.ReadInConfig(); err != nil {
		panic(err)
	}

	if err := v.Unmarshal(c); err != nil {
		panic(err)
	}
}

func (s *secret) readSecret() {
	v := viper.New()

	v.SetTypeByDefaultValue(true)
	v.SetConfigFile(os.Getenv("SECRETS_FILE_PATH"))
	s.v = v

	if err := v.ReadInConfig(); err != nil {
		panic(err)
	}

	if err := v.Unmarshal(s); err != nil {
		panic(err)
	}
}

func NewConfiguration() *AppConfig {
	config := &AppConfig{}
	config.readAppConfig()
	config.v.WatchConfig()
	config.v.OnConfigChange(func(in fsnotify.Event) {
		config.readAppConfig()
	})
	secrets := &secret{}
	secrets.readSecret()
	secrets.v.WatchConfig()
	secrets.v.OnConfigChange(func(in fsnotify.Event) {
		secrets.readSecret()
	})

	if masterKey, masterKeyPresent := os.LookupEnv("JWT_MASTER_KEY"); masterKeyPresent {
		config.Token.MasterKey = masterKey
	} else if secretKey, secretKeyPresent := os.LookupEnv("JWT_SECRET_KEY"); secretKeyPresent {
		config.Token.Secret = secretKey
	} else {
		slog.Error("One of token.secret or token.masterKey is required in config")
		os.Exit(1)
	}

	populatePostgresCredentials(secrets, config)

	if err := validateConfig(config); err != nil {
		slog.Error("invalid config", slog.Any("error", err))
		os.Exit(1)
	}

	return config
}

func populatePostgresCredentials(secret *secret, config *AppConfig) {
	if secret.Postgres.UserName != "" {
		config.Postgres.UserName = secret.Postgres.UserName
	} else if postgresUsername, postgresUsernamePresent := os.LookupEnv("POSTGRES_USER_NAME"); postgresUsernamePresent {
		config.Postgres.UserName = postgresUsername
	} else {
		slog.Error("POSTGRES_USER_NAME not found")
		os.Exit(1)
	}
	if secret.Postgres.Password != "" {
		config.Postgres.Password = secret.Postgres.Password
	} else if postgresPassword, postgresPasswordPresent := os.LookupEnv("POSTGRES_PASSWORD"); postgresPasswordPresent {
		config.Postgres.Password = postgresPassword
	} else {
		slog.Error("POSTGRES_PASSWORD not found")
		os.Exit(1)
	}
}

func validateConfig(cfg *AppConfig) error {
	validate := validator.New()
	if err := validate.Struct(cfg); err != nil {
		var validationErrors validator.ValidationErrors
		errors.As(err, &validationErrors)
		var errorMessages []string
		for _, e := range validationErrors {
			errorMessages = append(errorMessages, fmt.Sprintf("%s: %s", e.Field(), e.Tag()))
		}
		return fmt.Errorf("validation failed: %s", strings.Join(errorMessages, "; "))
	}
	return nil
}
