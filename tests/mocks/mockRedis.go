package mocks

import (
	"context"
	"testing"

	store "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/store"

	miniredis "github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func NewTestRedis(t *testing.T) (*store.Redis, *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err)

	client := goredis.NewClient(&goredis.Options{
		Addr: mr.Addr(),
		DB:   0,
	})

	rdb := &store.Redis{
		Client: client,
	}

	t.Cleanup(func() {
		_ = client.Close()
		mr.Close()
	})

	return rdb, mr
}

// -----------------------------------------------------------------------------
// User Version Helpers
// -----------------------------------------------------------------------------

// SetUserVersion sets the global token version for a user.
//
// This affects ALL sessions belonging to the user.
func SetUserVersion(t *testing.T, rdb *store.Redis, userID string, version int64) {
	t.Helper()

	err := rdb.Client.Set(
		context.Background(),
		"auth:user_version:"+userID,
		version,
		0,
	).Err()

	require.NoError(t, err)
}

// IncrementUserVersion increments the user's global token version.
//
// This simulates "logout everywhere".
func IncrementUserVersion(t *testing.T, rdb *store.Redis, userID string) int64 {
	t.Helper()

	version, err := rdb.IncrementUserVersion(
		context.Background(),
		userID,
	)

	require.NoError(t, err)

	return version
}

// GetUserVersion returns the current global token version for a user.
func GetUserVersion(t *testing.T, rdb *store.Redis, userID string) int64 {
	t.Helper()

	version, err := rdb.GetUserVersion(
		context.Background(),
		userID,
	)

	require.NoError(t, err)

	return version
}

// -----------------------------------------------------------------------------
// Session Helpers
// -----------------------------------------------------------------------------

// CreateSession creates a session in the test Redis.
//
// A new session starts at version 1.
func CreateSession(t *testing.T, rdb *store.Redis, sessionID string) {
	t.Helper()

	err := rdb.CreateSession(
		context.Background(),
		sessionID,
	)

	require.NoError(t, err)
}

// SetSessionVersion sets a specific session version.
//
// Useful when a test needs to start with a specific session version.
func SetSessionVersion(t *testing.T, rdb *store.Redis, sessionID string, version int64) {
	t.Helper()

	err := rdb.Client.Set(
		context.Background(),
		"auth:session:"+sessionID,
		version,
		0,
	).Err()

	require.NoError(t, err)
}

// GetSessionVersion returns the current version for a session.
func GetSessionVersion(t *testing.T, rdb *store.Redis, sessionID string) int64 {
	t.Helper()

	version, err := rdb.GetSessionVersion(
		context.Background(),
		sessionID,
	)

	require.NoError(t, err)

	return version
}

// IncrementSessionVersion increments a session's version.
//
// This simulates invalidating tokens for ONE session.
func IncrementSessionVersion(t *testing.T, rdb *store.Redis, sessionID string) int64 {
	t.Helper()

	version, err := rdb.IncrementSessionVersion(
		context.Background(),
		sessionID,
	)

	require.NoError(t, err)

	return version
}

// RevokeSession removes the session from Redis.
//
// This simulates logging out of one device/session.
func RevokeSession(t *testing.T, rdb *store.Redis, sessionID string) {
	t.Helper()

	err := rdb.RevokeSession(
		context.Background(),
		sessionID,
	)

	require.NoError(t, err)
}

// -----------------------------------------------------------------------------
// Token Validation Helper
// -----------------------------------------------------------------------------

// IsTokenValid checks whether a user's token is valid against the
// current user + session versions.
//
// This is useful for integration-style tests.
func IsTokenValid(t *testing.T, rdb *store.Redis, userID string, sessionID string, userVersion int64, sessionVersion int64) bool {
	t.Helper()

	valid, err := rdb.IsTokenValid(
		context.Background(),
		userID,
		sessionID,
		userVersion,
		sessionVersion,
	)

	require.NoError(t, err)

	return valid
}
