package tests

import (
	"context"
	"errors"
	"testing"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// LOGOUT
// ============================================================

func TestPublicIdentityService_Logout_Success(t *testing.T) {
	repo, mockTokens, svc := newPublicIdentityService(t)

	mockTokens.RevokeSessionFunc = func(
		ctx context.Context,
		sessionID string,
	) error {
		assert.Equal(t, "session-123", sessionID)

		return nil
	}

	resp, err := svc.Logout(
		context.Background(),
		&authv1.LogoutRequest{
			SessionId: "session-123",
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "logged out successfully", resp.Message)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_Logout_InvalidSessionID(t *testing.T) {
	repo, mockTokens, svc := newPublicIdentityService(t)

	mockTokens.RevokeSessionFunc = func(
		ctx context.Context,
		sessionID string,
	) error {
		assert.Equal(t, "", sessionID)

		return domain.ErrNotFound
	}

	resp, err := svc.Logout(
		context.Background(),
		&authv1.LogoutRequest{
			SessionId: "",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, domain.ErrInternal)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_Logout_RevokeSessionError(t *testing.T) {
	repo, mockTokens, svc := newPublicIdentityService(t)

	revokeErr := errors.New("redis unavailable")

	mockTokens.RevokeSessionFunc = func(
		ctx context.Context,
		sessionID string,
	) error {
		assert.Equal(t, "session-123", sessionID)

		return revokeErr
	}

	resp, err := svc.Logout(
		context.Background(),
		&authv1.LogoutRequest{
			SessionId: "session-123",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, domain.ErrInternal)

	repo.AssertExpectations(t)
}
