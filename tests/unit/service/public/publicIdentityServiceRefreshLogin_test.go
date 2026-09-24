package tests

import (
	"context"
	"errors"
	"os"
	"testing"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/tokens"

	"github.com/go-openapi/testify/v2/require"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// ============================================================
// TEST CONSTANTS
// ============================================================

const (
	testUserID    = "42"
	testSessionID = "session-123"
)

func TestMain(t *testing.M) {
	os.Setenv("ACCESS_SECRET", "test-access-secret")
	os.Setenv("REFRESH_SECRET", "test-refresh-secret")
	os.Exit(t.Run())
}

// ============================================================
// HELPERS
// ============================================================

func validClaims() *tokens.Claims {
	return &tokens.Claims{
		SessionID: testSessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: testUserID,
		},
	}
}

// ============================================================
// REFRESH TOKEN
// ============================================================

func TestRefreshToken_Success(t *testing.T) {
	var (
		validateCalled bool
		issueCalled    bool
		issuedUserID   string
		issuedSession  string
	)

	_, mockTokens, svc := newPublicIdentityService(t)

	mockTokens.ParseRefreshFunc = func(token string) (*tokens.Claims, error) {
		assert.Equal(t, "old-refresh-token", token)

		return validClaims(), nil
	}

	mockTokens.ValidateTokenFunc = func(
		ctx context.Context,
		claims *tokens.Claims,
	) (bool, error) {
		validateCalled = true

		assert.Equal(t, testUserID, claims.Subject)
		assert.Equal(t, testSessionID, claims.SessionID)

		return true, nil
	}

	mockTokens.IssueTokensForSessionFunc = func(
		ctx context.Context,
		userID string,
		sessionID string,
	) (*tokens.Tokens, error) {
		issueCalled = true
		issuedUserID = userID
		issuedSession = sessionID

		return &tokens.Tokens{
			Access:  "new-access-token",
			Refresh: "new-refresh-token",
		}, nil
	}

	resp, err := svc.RefreshLogin(
		context.Background(),
		&authv1.RefreshLoginRequest{
			RefreshToken: "old-refresh-token",
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "new-access-token", resp.AccessToken)
	assert.Equal(t, "new-refresh-token", resp.RefreshToken)

	assert.True(t, validateCalled)
	assert.True(t, issueCalled)

	// Refresh must preserve the original user and session.
	assert.Equal(t, testUserID, issuedUserID)
	assert.Equal(t, testSessionID, issuedSession)
}

func TestRefreshToken_ParseError(t *testing.T) {
	parseErr := errors.New("invalid refresh token")
	_, mockTokens, svc := newPublicIdentityService(t)

	mockTokens.ParseRefreshFunc = func(token string) (*tokens.Claims, error) {
		assert.Equal(t, "invalid-refresh-token", token)

		return nil, parseErr
	}

	resp, err := svc.RefreshLogin(
		context.Background(),
		&authv1.RefreshLoginRequest{
			RefreshToken: "invalid-refresh-token",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, domain.ErrUnauthorized)
}

func TestRefreshToken_ValidationReturnsFalse(t *testing.T) {
	validateCalled := false
	issueCalled := false

	_, mockTokens, svc := newPublicIdentityService(t)

	mockTokens.ParseRefreshFunc = func(token string) (*tokens.Claims, error) {
		return validClaims(), nil
	}

	mockTokens.ValidateTokenFunc = func(
		ctx context.Context,
		claims *tokens.Claims,
	) (bool, error) {
		validateCalled = true

		assert.Equal(t, testUserID, claims.Subject)
		assert.Equal(t, testSessionID, claims.SessionID)

		return false, nil
	}

	mockTokens.IssueTokensForSessionFunc = func(
		ctx context.Context,
		userID string,
		sessionID string,
	) (*tokens.Tokens, error) {
		issueCalled = true

		return &tokens.Tokens{
			Access:  "should-not-be-issued",
			Refresh: "should-not-be-issued",
		}, nil
	}

	resp, err := svc.RefreshLogin(
		context.Background(),
		&authv1.RefreshLoginRequest{
			RefreshToken: "revoked-refresh-token",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, domain.ErrUnauthorized)

	assert.True(t, validateCalled)
	assert.False(t, issueCalled)
}

func TestRefreshToken_ValidationError(t *testing.T) {
	validationErr := errors.New("token validation failed")
	issueCalled := false

	_, mockTokens, svc := newPublicIdentityService(t)

	mockTokens.ParseRefreshFunc = func(token string) (*tokens.Claims, error) {
		return validClaims(), nil
	}

	mockTokens.ValidateTokenFunc = func(
		ctx context.Context,
		claims *tokens.Claims,
	) (bool, error) {
		return false, validationErr
	}

	mockTokens.IssueTokensForSessionFunc = func(
		ctx context.Context,
		userID string,
		sessionID string,
	) (*tokens.Tokens, error) {
		issueCalled = true

		return nil, nil
	}

	resp, err := svc.RefreshLogin(
		context.Background(),
		&authv1.RefreshLoginRequest{
			RefreshToken: "valid-refresh-token",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, domain.ErrUnauthorized)

	// Do not issue tokens when validation itself failed.
	assert.False(t, issueCalled)
}

func TestRefreshToken_IssueTokensError(t *testing.T) {
	issueErr := errors.New("failed to issue tokens")

	_, mockTokens, svc := newPublicIdentityService(t)

	mockTokens.ParseRefreshFunc = func(token string) (*tokens.Claims, error) {
		return validClaims(), nil
	}

	mockTokens.ValidateTokenFunc = func(
		ctx context.Context,
		claims *tokens.Claims,
	) (bool, error) {
		return true, nil
	}

	mockTokens.IssueTokensForSessionFunc = func(
		ctx context.Context,
		userID string,
		sessionID string,
	) (*tokens.Tokens, error) {
		assert.Equal(t, testUserID, userID)
		assert.Equal(t, testSessionID, sessionID)

		return nil, issueErr
	}

	resp, err := svc.RefreshLogin(
		context.Background(),
		&authv1.RefreshLoginRequest{
			RefreshToken: "valid-refresh-token",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, domain.ErrInternal)
}

func TestRefreshToken_DoesNotIssueTokensWhenParsingFails(t *testing.T) {
	issueCalled := false

	_, mockTokens, svc := newPublicIdentityService(t)
	mockTokens.ParseRefreshFunc = func(token string) (*tokens.Claims, error) {
		return nil, errors.New("bad refresh token")
	}

	mockTokens.IssueTokensForSessionFunc = func(
		ctx context.Context,
		userID string,
		sessionID string,
	) (*tokens.Tokens, error) {
		issueCalled = true

		return nil, nil
	}

	resp, err := svc.RefreshLogin(
		context.Background(),
		&authv1.RefreshLoginRequest{
			RefreshToken: "bad-token",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, domain.ErrUnauthorized)
	assert.False(t, issueCalled)
}
