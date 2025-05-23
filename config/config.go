package config

import (
	"encoding/base64"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type AppConfig struct {
	v     *viper.Viper
	Token Token `required:"true" json:"token" yaml:"token"`
}

type Token struct {
	Secret         string `json:"secretKey" yaml:"secret"`
	MasterKey      string `json:"masterKey" yaml:"masterKey"`
	Bearer         Bearer `required:"true" json:"bearer" yaml:"bearer"`
	RefreshRefresh Bearer `required:"true" json:"refresh" yaml:"refresh"`
}

type Bearer struct {
	TTL time.Duration `required:"true" json:"ttl" yaml:"ttl"`
}

type Refresh struct {
	TTL time.Duration `required:"true" json:"ttl" yaml:"ttl"`
}

type secret struct {
	v   *viper.Viper
	JWT JWT `required:"true" json:"jwt" yaml:"jwt"`
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

	if masterKey, masterKeyPresent := os.LookupEnv("JWT_MASTER_KEY"); masterKeyPresent {
		s.JWT.MasterKey = masterKey
	} else if secretKey, secretKeyPresent := os.LookupEnv("JWT_SECRET_KEY"); secretKeyPresent {
		s.JWT.SecretKey = secretKey
	} else {
		log.Fatal().Msg("One of token.secret or token.masterKey is required in config")
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
	if secret.JWT.MasterKey != "" {
		if masterByte, err := base64.StdEncoding.DecodeString(secret.JWT.MasterKey); err == nil {
			config.Token.MasterKey = string(masterByte)
		} else {
			log.Fatal().Msg("Decoding master key failed")
		}
	} else {
		if secretByte, err := base64.StdEncoding.DecodeString(secret.JWT.SecretKey); err == nil {
			config.Token.Secret = string(secretByte)
		} else {
			log.Fatal().Msg("Decoding jwt secret failed")
		}
	}
	return config
}
