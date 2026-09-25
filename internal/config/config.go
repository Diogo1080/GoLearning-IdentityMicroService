package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const minimumSecretLength = 32

type Config struct {
	AppEnv   string
	AppPort  string
	GRPCPort string

	Database DatabaseConfig
	Redis    RedisConfig
	Tokens   TokenConfig
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string
}

type RedisConfig struct {
	Host     string
	Port     string
	Password string
}

type TokenConfig struct {
	AccessSecret  string
	RefreshSecret string
}

func Load() (Config, error) {
	cfg := Config{
		AppEnv:   envOrDefault("APP_ENV", "development"),
		AppPort:  envOrDefault("APP_PORT", "9000"),
		GRPCPort: envOrDefault("GRPC_PORT", "50051"),
		Database: DatabaseConfig{
			Host:     envOrDefault("DB_HOST", "localhost"),
			Port:     envOrDefault("DB_PORT", "5432"),
			User:     os.Getenv("DB_USER"),
			Password: os.Getenv("DB_SECRET"),
			Name:     os.Getenv("DB_NAME"),
			SSLMode:  envOrDefault("DB_SSLMODE", "disable"),
		},
		Redis: RedisConfig{
			Host:     envOrDefault("REDIS_HOST", "localhost"),
			Port:     envOrDefault("REDIS_PORT", "6379"),
			Password: os.Getenv("REDIS_PASSWORD"),
		},
		Tokens: TokenConfig{
			AccessSecret:  os.Getenv("ACCESS_SECRET"),
			RefreshSecret: os.Getenv("REFRESH_SECRET"),
		},
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	var missing []string
	for name, value := range map[string]string{
		"DB_USER":        c.Database.User,
		"DB_SECRET":      c.Database.Password,
		"DB_NAME":        c.Database.Name,
		"ACCESS_SECRET":  c.Tokens.AccessSecret,
		"REFRESH_SECRET": c.Tokens.RefreshSecret,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	for name, value := range map[string]string{
		"APP_PORT":   c.AppPort,
		"GRPC_PORT":  c.GRPCPort,
		"DB_PORT":    c.Database.Port,
		"REDIS_PORT": c.Redis.Port,
	} {
		if err := validatePort(name, value); err != nil {
			return err
		}
	}

	for name, value := range map[string]string{
		"ACCESS_SECRET":  c.Tokens.AccessSecret,
		"REFRESH_SECRET": c.Tokens.RefreshSecret,
	} {
		if len(value) < minimumSecretLength {
			return fmt.Errorf("%s must be at least %d characters", name, minimumSecretLength)
		}
	}

	if c.Database.SSLMode == "" {
		return errors.New("DB_SSLMODE must not be empty")
	}
	return nil
}

func (c Config) DatabaseURL() string {
	connectionURL := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(c.Database.User, c.Database.Password),
		Host:   net.JoinHostPort(c.Database.Host, c.Database.Port),
		Path:   "/" + c.Database.Name,
	}
	query := connectionURL.Query()
	query.Set("sslmode", c.Database.SSLMode)
	connectionURL.RawQuery = query.Encode()
	return connectionURL.String()
}

func validatePort(name, value string) error {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s must be a valid port: %q", name, value)
	}
	return nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
