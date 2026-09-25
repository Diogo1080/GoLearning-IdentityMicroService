package config_test

import (
	"strings"
	"testing"

	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/config"
)

func setValidEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("APP_PORT", "9000")
	t.Setenv("GRPC_PORT", "50051")
	t.Setenv("DB_USER", "identity")
	t.Setenv("DB_SECRET", "database-secret")
	t.Setenv("DB_NAME", "identity")
	t.Setenv("ACCESS_SECRET", strings.Repeat("a", 32))
	t.Setenv("REFRESH_SECRET", strings.Repeat("b", 32))
}

func TestLoadUsesDevelopmentDefaults(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("DB_HOST", "")
	t.Setenv("DB_PORT", "")
	t.Setenv("DB_SSLMODE", "")
	t.Setenv("REDIS_HOST", "")
	t.Setenv("REDIS_PORT", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.AppPort != "9000" || cfg.GRPCPort != "50051" {
		t.Fatalf("unexpected server defaults: %+v", cfg)
	}
	if cfg.Database.Host != "localhost" || cfg.Database.Port != "5432" {
		t.Fatalf("unexpected database defaults: %+v", cfg.Database)
	}
	if cfg.Redis.Host != "localhost" || cfg.Redis.Port != "6379" {
		t.Fatalf("unexpected Redis defaults: %+v", cfg.Redis)
	}
}

func TestLoadRejectsShortSecrets(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("ACCESS_SECRET", "short")

	_, err := config.Load()
	if err == nil || !strings.Contains(err.Error(), "ACCESS_SECRET") {
		t.Fatalf("expected ACCESS_SECRET validation error, got %v", err)
	}
}

func TestLoadRejectsInvalidPort(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("APP_PORT", "not-a-port")

	_, err := config.Load()
	if err == nil || !strings.Contains(err.Error(), "APP_PORT") {
		t.Fatalf("expected APP_PORT validation error, got %v", err)
	}
}

func TestDatabaseURLEscapesCredentials(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("DB_USER", "user@example.com")
	t.Setenv("DB_SECRET", "password:with/slash")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !strings.Contains(cfg.DatabaseURL(), "user%40example.com") || !strings.Contains(cfg.DatabaseURL(), "password%3Awith%2Fslash") {
		t.Fatalf("DatabaseURL() did not escape credentials: %s", cfg.DatabaseURL())
	}
}
