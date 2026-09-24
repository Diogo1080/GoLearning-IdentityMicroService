package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func RunMigrations(db *sql.DB) error {
	ctx := context.Background()
	migrationConn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open migration connection: %w", err)
	}

	databaseDriver, err := postgres.WithConnection(ctx, migrationConn, &postgres.Config{})
	if err != nil {
		_ = migrationConn.Close()
		return fmt.Errorf("create migration database driver: %w", err)
	}

	sourceDriver, err := iofs.New(migrationFiles, "migrations")
	if err != nil {
		_ = databaseDriver.Close()
		return fmt.Errorf("create migration source driver: %w", err)
	}

	migrationRunner, err := migrate.NewWithInstance("iofs", sourceDriver, "postgres", databaseDriver)
	if err != nil {
		_ = databaseDriver.Close()
		return fmt.Errorf("create migration runner: %w", err)
	}
	defer func() {
		_, _ = migrationRunner.Close()
	}()

	if err := migrationRunner.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("apply migrations: %w", err)
	}

	return nil
}
