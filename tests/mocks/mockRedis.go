package mocks

import (
	"context"
	"testing"
	"time"

	store "GoLearning-IdentityMicroService/internal/store"

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

func SetJTI(
	t *testing.T,
	rdb *store.Redis,
	key string,
	userID string,
	exp time.Time,
) {
	t.Helper()

	err := rdb.SetJTI(
		context.Background(),
		key,
		userID,
		exp,
	)

	require.NoError(t, err)
}
