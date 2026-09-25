package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/redis/go-redis/v9"
)

var (
	ErrInvalidUserVersion    = errors.New("invalid user token version")
	ErrInvalidSessionVersion = errors.New("invalid session token version")
	ErrSessionNotFound       = errors.New("session not found")
)

type Redis struct {
	Client *redis.Client
}

func NewRedis(host, port, password string) *Redis {
	addr := fmt.Sprintf("%s:%s", host, port)

	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       0,
	})

	return &Redis{
		Client: rdb,
	}
}

// -----------------------------------------------------------------------------
// Keys
// -----------------------------------------------------------------------------

func userVersionKey(userID string) string {
	return "auth:user_version:" + userID
}

func sessionKey(sessionID string) string {
	return "auth:session:" + sessionID
}

// -----------------------------------------------------------------------------
// User Token Version
// -----------------------------------------------------------------------------
//
// The user version is shared by ALL sessions belonging to a user.
//
// Incrementing the user version invalidates every existing token for that user, regardless of session.
//

// GetUserVersion returns the current token version for a user.
//
// If the user has no version yet, version 1 is returned.
//
// Missing keys are treated as version 1 rather than being created.
// This keeps reads side-effect free.
func (r *Redis) GetUserVersion(ctx context.Context, userID string) (int64, error) {
	value, err := r.Client.Get(ctx, userVersionKey(userID)).Result()

	if err == redis.Nil {
		return 1, nil
	}

	if err != nil {
		return 0, err
	}

	version, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf(
			"invalid user token version in redis: %w",
			err,
		)
	}

	if version < 1 {
		return 0, ErrInvalidUserVersion
	}

	return version, nil
}

// InitializeUserVersion creates the user's version if it doesn't exist.
//
// This is optional because GetUserVersion treats a missing key as version 1.
func (r *Redis) InitializeUserVersion(ctx context.Context, userID string) error {
	return r.Client.SetNX(
		ctx,
		userVersionKey(userID),
		1,
		0,
	).Err()
}

// IncrementUserVersion invalidates ALL sessions/tokens belonging
// to the user.
//
// All existing JWTs containing user_version=5 are now invalid.
func (r *Redis) IncrementUserVersion(ctx context.Context, userID string) (int64, error) {
	return r.Client.Incr(
		ctx,
		userVersionKey(userID),
	).Result()
}

// Every login gets its own session ID.
// Revoking/incrementing one session does not affect other sessions.
// CreateSession creates a new session at version 1.
func (r *Redis) CreateSession(ctx context.Context, sessionID string) error {
	return r.Client.Set(
		ctx,
		sessionKey(sessionID),
		1,
		0,
	).Err()
}

// GetSessionVersion returns the current token version for a session.
//
// A missing session means that the session has been revoked/invalidated.
func (r *Redis) GetSessionVersion(ctx context.Context, sessionID string) (int64, error) {
	value, err := r.Client.Get(
		ctx,
		sessionKey(sessionID),
	).Result()

	if err == redis.Nil {
		return 0, ErrSessionNotFound
	}

	if err != nil {
		return 0, err
	}

	version, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf(
			"invalid session token version in redis: %w",
			err,
		)
	}

	if version < 1 {
		return 0, ErrInvalidSessionVersion
	}

	return version, nil
}

// IncrementSessionVersion invalidates all tokens belonging to ONE session.
//
// Other sessions belonging to the same user remain valid.
func (r *Redis) IncrementSessionVersion(ctx context.Context, sessionID string) (int64, error) {
	// Make sure the session actually exists.
	exists, err := r.Client.Exists(
		ctx,
		sessionKey(sessionID),
	).Result()

	if err != nil {
		return 0, err
	}

	if exists == 0 {
		return 0, ErrSessionNotFound
	}

	return r.Client.Incr(
		ctx,
		sessionKey(sessionID),
	).Result()
}

// RevokeSession completely removes a session.
//
// Once removed, every token containing this session ID becomes invalid.
func (r *Redis) RevokeSession(ctx context.Context, sessionID string) error {
	result, err := r.Client.Del(
		ctx,
		sessionKey(sessionID),
	).Result()

	if err != nil {
		return err
	}

	if result == 0 {
		return ErrSessionNotFound
	}

	return nil
}

// -----------------------------------------------------------------------------
// Token Validation
// -----------------------------------------------------------------------------

// IsTokenValid verifies BOTH:
//
//  1. The user token version matches.
//  2. The session token version matches.
//
// A token is valid only when BOTH versions match.
func (r *Redis) IsTokenValid(ctx context.Context, userID string, sessionID string, tokenUserVersion int64, tokenSessionVersion int64) (bool, error) {
	currentUserVersion, err := r.GetUserVersion(ctx, userID)
	if err != nil {
		return false, err
	}

	if tokenUserVersion != currentUserVersion {
		return false, nil
	}

	currentSessionVersion, err := r.GetSessionVersion(ctx, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return false, nil
		}

		return false, err
	}

	if tokenSessionVersion != currentSessionVersion {
		return false, nil
	}

	return true, nil
}
