package tests

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"GoLearning-IdentityMicroService/internal/tokens"
	"context"
	"testing"

	"github.com/go-openapi/testify/v2/require"
	"github.com/stretchr/testify/assert"
)

// ============================================================
// LOGOUT
// ============================================================

func TestPublicIdentityService_Logout_Success(t *testing.T) {
	repo, rdb, svc := newPublicIdentityService(t)

	tokenPair := issueTestTokens(t)
	persistAccessToken(t, rdb, tokenPair.Access)

	claims, err := tokens.ParseAccess(tokenPair.Access)
	require.NoError(t, err)

	resp, err := svc.Logout(
		context.Background(),
		&authv1.LogoutRequest{
			Token: tokenPair.Access,
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "logged out successfully", resp.Message)

	// JTI should no longer exist.
	_, err = rdb.GetUserByJTI(
		context.Background(),
		"access:"+claims.ID,
	)

	assert.Error(t, err)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_Logout_InvalidToken(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	resp, err := svc.Logout(
		context.Background(),
		&authv1.LogoutRequest{
			Token: "invalid-token",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrBadData)

	repo.AssertExpectations(t)
}
