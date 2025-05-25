package config

import (
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type AppConfig struct {
	v        *viper.Viper
	Token    Token          `required:"true" json:"token" yaml:"token"`
	Postgres PostgresConfig `required:"true" json:"postgres" yaml:"postgres"`
}

type Token struct {
	Secret         string `json:"secretKey" yaml:"secret"`
	MasterKey      string `json:"masterKey" yaml:"masterKey"`
	Bearer         Bearer `required:"true" json:"bearer" yaml:"bearer"`
	RefreshRefresh Bearer `required:"true" json:"refresh" yaml:"refresh"`
}

type PostgresConfig struct {
	Host     string        `required:"true" json:"host" yaml:"host"`
	Port     string        `json:"port" yaml:"port"`
	DBName   string        `required:"true" json:"dbName" yaml:"dbName"`
	UserName string        `required:"true" json:"username" yaml:"username"`
	Password string        `required:"true" json:"password" yaml:"password"`
	SSLMode  string        `required:"true" json:"sslMode" yaml:"sslMode"`
	Timeout  time.Duration `required:"true" json:"timeout" yaml:"timeout"`
	MaxRetry int           `required:"true" json:"maxRetry" yaml:"maxRetry"`
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
	secret := &secret{}
	secret.readSecret()
	secret.v.WatchConfig()
	secret.v.OnConfigChange(func(in fsnotify.Event) {
		secret.readSecret()
	})

	if masterKey, masterKeyPresent := os.LookupEnv("JWT_MASTER_KEY"); masterKeyPresent {
		config.Token.MasterKey = masterKey
	} else if secretKey, secretKeyPresent := os.LookupEnv("JWT_SECRET_KEY"); secretKeyPresent {
		config.Token.Secret = secretKey
	} else {
		log.Fatal().Msg("One of token.secret or token.masterKey is required in config")
	}

	populatePostgresCredentials(secret, config)

	return config
}

func populatePostgresCredentials(secret *secret, config *AppConfig) {
	if secret.Postgres.UserName != "" {
		config.Postgres.UserName = secret.Postgres.UserName
	} else if postgresUsername, postgresUsernamePresent := os.LookupEnv("POSTGRES_USER_NAME"); postgresUsernamePresent {
		config.Postgres.UserName = postgresUsername
	} else {
		log.Fatal().Msg("POSTGRES_USER_NAME not found")
	}
	if secret.Postgres.Password != "" {
		config.Postgres.Password = secret.Postgres.Password
	} else if postgresPassword, postgresPasswordPresent := os.LookupEnv("POSTGRES_PASSWORD"); postgresPasswordPresent {
		config.Postgres.Password = postgresPassword
	} else {
		log.Fatal().Msg("POSTGRES_PASSWORD not found")
	}
}
