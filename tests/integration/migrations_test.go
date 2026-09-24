package integration

import (
	"database/sql"
	"os"
	"testing"

	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/store"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func migrationTestDatabase(t *testing.T) *sql.DB {
	t.Helper()

	databaseURL := os.Getenv("MIGRATION_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("MIGRATION_TEST_DATABASE_URL is not configured")
	}

	db, err := sql.Open("postgres", databaseURL)
	require.NoError(t, err)
	require.NoError(t, db.Ping())

	t.Cleanup(func() {
		_, _ = db.Exec("DROP TABLE IF EXISTS users CASCADE")
		_, _ = db.Exec("DROP TABLE IF EXISTS schema_migrations")
		_ = db.Close()
	})

	return db
}

func resetMigrationDatabase(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec("DROP TABLE IF EXISTS users CASCADE")
	require.NoError(t, err)
	_, err = db.Exec("DROP TABLE IF EXISTS schema_migrations")
	require.NoError(t, err)
}

func assertUsersTableExists(t *testing.T, db *sql.DB) {
	t.Helper()

	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'users'
		)`).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists)
}

func TestRunMigrationsFromEmptyDatabase(t *testing.T) {
	db := migrationTestDatabase(t)
	resetMigrationDatabase(t, db)

	require.NoError(t, store.RunMigrations(db))
	assertUsersTableExists(t, db)
}

func TestRunMigrationsFromPreviousUsersSchema(t *testing.T) {
	db := migrationTestDatabase(t)
	resetMigrationDatabase(t, db)

	_, err := db.Exec(`
		CREATE TABLE users (
			id SERIAL PRIMARY KEY,
			email VARCHAR(255) NOT NULL UNIQUE,
			username VARCHAR(255) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			birthdate DATE,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			deleted_at TIMESTAMP
		)`)
	require.NoError(t, err)

	require.NoError(t, store.RunMigrations(db))
	assertUsersTableExists(t, db)
}
