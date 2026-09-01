package tests

import (
	"context"
	"os"
	"testing"
	"time"

	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"GoLearning-IdentityMicroService/internal/service"

	"GoLearning-IdentityMicroService/internal/tokens"
	"GoLearning-IdentityMicroService/tests/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(t *testing.M) {
	os.Setenv("ACCESS_SECRET", "test-access-secret")
	os.Setenv("REFRESH_SECRET", "test-refresh-secret")
	os.Exit(t.Run())
}

// ============================================================
// VALIDATE TOKEN
// ============================================================

func TestValidateToken_Success(t *testing.T) {
	rdb, _ := mocks.NewTestRedis(t)
	mockIdentityRepo := &mocks.MockIdentityRepository{}

	svc := service.NewInternalIdentityService(mockIdentityRepo, rdb)

	tokenPair := issueTestTokens(t)

	persistAccessToken(t, rdb, tokenPair.Access)

	resp, err := svc.ValidateToken(
		context.Background(),
		&authv1.ValidateTokenRequest{
			Token: tokenPair.Access,
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, int32(42), resp.UserId)
}

func TestValidateToken_InvalidToken(t *testing.T) {
	rdb, _ := mocks.NewTestRedis(t)
	mockIdentityRepo := &mocks.MockIdentityRepository{}
	svc := service.NewInternalIdentityService(mockIdentityRepo, rdb)

	resp, err := svc.ValidateToken(
		context.Background(),
		&authv1.ValidateTokenRequest{
			Token: "invalid-token",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrBadData)
}

func TestValidateToken_TokenNotFoundInRedis(t *testing.T) {
	rdb, _ := mocks.NewTestRedis(t)
	mockIdentityRepo := &mocks.MockIdentityRepository{}
	svc := service.NewInternalIdentityService(mockIdentityRepo, rdb)

	tokenPair := issueTestTokens(t)

	// JWT is valid, but its JTI is not in Redis.
	resp, err := svc.ValidateToken(
		context.Background(),
		&authv1.ValidateTokenRequest{
			Token: tokenPair.Access,
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrNotFound)
}

func TestValidateToken_ExpiredRedisEntry(t *testing.T) {
	rdb, mr := mocks.NewTestRedis(t)
	mockIdentityRepo := &mocks.MockIdentityRepository{}
	svc := service.NewInternalIdentityService(mockIdentityRepo, rdb)

	tokenPair := issueTestTokens(t)

	claims, err := tokens.ParseAccess(tokenPair.Access)
	require.NoError(t, err)

	err = rdb.SetJTI(
		context.Background(),
		"access:"+claims.ID,
		testUserIdString,
		time.Now().Add(1*time.Minute),
	)
	require.NoError(t, err)

	// Simulate Redis TTL expiration.
	mr.FastForward(2 * time.Minute)

	resp, err := svc.ValidateToken(
		context.Background(),
		&authv1.ValidateTokenRequest{
			Token: tokenPair.Access,
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrNotFound)
}

// ============================================================
// REFRESH TOKEN
// ============================================================

func TestRefreshToken_Success(t *testing.T) {
	rdb, _ := mocks.NewTestRedis(t)
	mockIdentityRepo := &mocks.MockIdentityRepository{}
	svc := service.NewInternalIdentityService(mockIdentityRepo, rdb)

	oldTokens := issueTestTokens(t)

	persistRefreshToken(t, rdb, oldTokens.Refresh)

	oldClaims, err := tokens.ParseRefresh(oldTokens.Refresh)
	require.NoError(t, err)

	resp, err := svc.RefreshToken(
		context.Background(),
		&authv1.RefreshTokenRequest{
			RefreshToken: oldTokens.Refresh,
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)

	// Verify the new access token.
	newAccessClaims, err := tokens.ParseAccess(resp.AccessToken)
	require.NoError(t, err)

	assert.Equal(t, testUserIdString, newAccessClaims.Subject)

	// Verify the new refresh token.
	newRefreshClaims, err := tokens.ParseRefresh(resp.RefreshToken)
	require.NoError(t, err)

	assert.Equal(t, testUserIdString, newRefreshClaims.Subject)

	// A refresh should issue a new JTI.
	assert.NotEqual(t, oldClaims.ID, newRefreshClaims.ID)
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	rdb, _ := mocks.NewTestRedis(t)
	mockIdentityRepo := &mocks.MockIdentityRepository{}
	svc := service.NewInternalIdentityService(mockIdentityRepo, rdb)

	resp, err := svc.RefreshToken(
		context.Background(),
		&authv1.RefreshTokenRequest{
			RefreshToken: "invalid-refresh-token",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrBadData)
}

func TestRefreshToken_TokenNotFoundInRedis(t *testing.T) {
	rdb, _ := mocks.NewTestRedis(t)
	mockIdentityRepo := &mocks.MockIdentityRepository{}
	svc := service.NewInternalIdentityService(mockIdentityRepo, rdb)

	tokenPair := issueTestTokens(t)

	// Valid JWT, but refresh JTI isn't in Redis.
	resp, err := svc.RefreshToken(
		context.Background(),
		&authv1.RefreshTokenRequest{
			RefreshToken: tokenPair.Refresh,
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrNotFound)
}

func TestRefreshToken_ExpiredRedisEntry(t *testing.T) {
	rdb, mr := mocks.NewTestRedis(t)
	mockIdentityRepo := &mocks.MockIdentityRepository{}
	svc := service.NewInternalIdentityService(mockIdentityRepo, rdb)

	tokenPair := issueTestTokens(t)

	claims, err := tokens.ParseRefresh(tokenPair.Refresh)
	require.NoError(t, err)

	err = rdb.SetJTI(
		context.Background(),
		"refresh:"+claims.ID,
		testUserIdString,
		time.Now().Add(1*time.Minute),
	)
	require.NoError(t, err)

	// Simulate Redis TTL expiration.
	mr.FastForward(2 * time.Minute)

	resp, err := svc.RefreshToken(
		context.Background(),
		&authv1.RefreshTokenRequest{
			RefreshToken: tokenPair.Refresh,
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrNotFound)
}
