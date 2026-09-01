package tests

import (
	"GoLearning-IdentityMicroService/internal/service"
	"GoLearning-IdentityMicroService/internal/store"
	"GoLearning-IdentityMicroService/internal/tests/mocks"
	"GoLearning-IdentityMicroService/internal/tokens"
	"context"
	"time"

	"GoLearning-IdentityMicroService/internal/domain"

	"testing"

	"github.com/go-openapi/testify/v2/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	testUserIdString = "42"
	testUserId       = 42
	testUsername     = "john_doe"
	testEmail        = "john@example.com"
	testPassword     = "password123"
	testJWTSecret    = "test-secret"
)

func newPublicIdentityService(t *testing.T) (
	*mocks.MockIdentityRepository,
	*store.Redis,
	*service.PublicIdentityService,
) {
	t.Helper()

	rdb, _ := mocks.NewTestRedis(t)
	repo := &mocks.MockIdentityRepository{}

	svc := service.NewPublicIdentityService(repo, rdb)

	return repo, rdb, svc
}

func testUser() domain.User {
	hashedPassword, err := service.HashPassword(testPassword)
	if err != nil {
		panic(err)
	}

	return domain.User{
		ID:       int64(testUserId),
		Username: testUsername,
		Email:    testEmail,
		Password: hashedPassword,
	}
}

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

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// VerifyPassword verifies if the given password matches the stored hash.
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
