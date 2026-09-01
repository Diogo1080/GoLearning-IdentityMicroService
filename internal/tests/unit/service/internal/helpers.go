package tests

import (
	"context"
	"testing"
	"time"

	store "GoLearning-IdentityMicroService/internal/store"

	"GoLearning-IdentityMicroService/internal/tokens"

	"github.com/go-openapi/testify/v2/require"
)

const (
	testUserIdString = "42"
)

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

func issueTestTokens(t *testing.T) *tokens.Tokens {
	t.Helper()

	tokenPair, err := tokens.IssueTokens(testUserIdString)
	require.NoError(t, err)
	require.NotNil(t, tokenPair)

	return tokenPair
}

func persistAccessToken(t *testing.T, rdb *store.Redis, accessToken string) {
	t.Helper()

	claims, err := tokens.ParseAccess(accessToken)
	require.NoError(t, err)

	err = rdb.SetJTI(
		context.Background(),
		"access:"+claims.ID,
		testUserIdString,
		time.Now().Add(15*time.Minute),
	)
	require.NoError(t, err)
}

func persistRefreshToken(t *testing.T, rdb *store.Redis, refreshToken string) {
	t.Helper()

	claims, err := tokens.ParseRefresh(refreshToken)
	require.NoError(t, err)

	err = rdb.SetJTI(
		context.Background(),
		"refresh:"+claims.ID,
		testUserIdString,
		time.Now().Add(7*24*time.Hour),
	)
	require.NoError(t, err)
}
