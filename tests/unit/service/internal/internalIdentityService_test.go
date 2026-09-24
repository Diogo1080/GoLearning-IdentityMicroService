package tests

import (
	"context"
	"errors"
	"os"
	"testing"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	entities "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/service"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/tokens"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/tests/mocks"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func newService(mockTokens *mocks.MockTokenManager) *service.InternalIdentityService {
	mockIdentityRepo := &mocks.MockIdentityRepository{}

	return service.NewInternalIdentityService(
		mockIdentityRepo,
		mockTokens,
	)
}

func validClaims() *tokens.Claims {
	return &tokens.Claims{
		SessionID: testSessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: testUserID,
		},
	}
}

// ============================================================
// VALIDATE TOKEN
// ============================================================

func TestValidateToken_Success(t *testing.T) {
	mockTokens := &mocks.MockTokenManager{
		ParseAccessFunc: func(token string) (*tokens.Claims, error) {
			assert.Equal(t, "valid-access-token", token)

			return validClaims(), nil
		},

		ValidateTokenFunc: func(
			ctx context.Context,
			claims *tokens.Claims,
		) (bool, error) {
			assert.Equal(t, testUserID, claims.Subject)
			assert.Equal(t, testSessionID, claims.SessionID)

			return true, nil
		},
	}

	svc := newService(mockTokens)

	resp, err := svc.ValidateToken(
		context.Background(),
		&authv1.ValidateTokenRequest{
			Token: "valid-access-token",
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, int32(42), resp.UserId)
}

func TestValidateToken_ParseError(t *testing.T) {
	parseErr := errors.New("invalid access token")

	mockTokens := &mocks.MockTokenManager{
		ParseAccessFunc: func(token string) (*tokens.Claims, error) {
			assert.Equal(t, "invalid-token", token)

			return nil, parseErr
		},
	}

	svc := newService(mockTokens)

	resp, err := svc.ValidateToken(
		context.Background(),
		&authv1.ValidateTokenRequest{
			Token: "invalid-token",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrUnauthorized)
}

func TestValidateToken_ValidationReturnsFalse(t *testing.T) {
	validateCalled := false

	mockTokens := &mocks.MockTokenManager{
		ParseAccessFunc: func(token string) (*tokens.Claims, error) {
			return validClaims(), nil
		},

		ValidateTokenFunc: func(
			ctx context.Context,
			claims *tokens.Claims,
		) (bool, error) {
			validateCalled = true

			assert.Equal(t, testUserID, claims.Subject)
			assert.Equal(t, testSessionID, claims.SessionID)

			return false, nil
		},
	}

	svc := newService(mockTokens)

	resp, err := svc.ValidateToken(
		context.Background(),
		&authv1.ValidateTokenRequest{
			Token: "revoked-token",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrUnauthorized)
	assert.True(t, validateCalled)
}

func TestValidateToken_ValidationError(t *testing.T) {
	validationErr := errors.New("token validation failed")

	mockTokens := &mocks.MockTokenManager{
		ParseAccessFunc: func(token string) (*tokens.Claims, error) {
			return validClaims(), nil
		},

		ValidateTokenFunc: func(
			ctx context.Context,
			claims *tokens.Claims,
		) (bool, error) {
			return false, validationErr
		},
	}

	svc := newService(mockTokens)

	resp, err := svc.ValidateToken(
		context.Background(),
		&authv1.ValidateTokenRequest{
			Token: "valid-token",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrInternal)
}

func TestValidateToken_InvalidUserID(t *testing.T) {
	mockTokens := &mocks.MockTokenManager{
		ParseAccessFunc: func(token string) (*tokens.Claims, error) {
			return &tokens.Claims{
				SessionID: testSessionID,
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "not-a-number",
				},
			}, nil
		},

		ValidateTokenFunc: func(
			ctx context.Context,
			claims *tokens.Claims,
		) (bool, error) {
			return true, nil
		},
	}

	svc := newService(mockTokens)

	resp, err := svc.ValidateToken(
		context.Background(),
		&authv1.ValidateTokenRequest{
			Token: "valid-token",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrInternal)
}

func TestValidateToken_UserIDTooLargeForInt32(t *testing.T) {
	mockTokens := &mocks.MockTokenManager{
		ParseAccessFunc: func(token string) (*tokens.Claims, error) {
			return &tokens.Claims{
				SessionID: testSessionID,
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "2147483648",
				},
			}, nil
		},

		ValidateTokenFunc: func(
			ctx context.Context,
			claims *tokens.Claims,
		) (bool, error) {
			return true, nil
		},
	}

	svc := newService(mockTokens)

	resp, err := svc.ValidateToken(
		context.Background(),
		&authv1.ValidateTokenRequest{
			Token: "valid-token",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrInternal)
}

func TestValidateToken_NegativeUserID(t *testing.T) {
	mockTokens := &mocks.MockTokenManager{
		ParseAccessFunc: func(token string) (*tokens.Claims, error) {
			return &tokens.Claims{
				SessionID: testSessionID,
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "-42",
				},
			}, nil
		},

		ValidateTokenFunc: func(
			ctx context.Context,
			claims *tokens.Claims,
		) (bool, error) {
			return true, nil
		},
	}

	svc := newService(mockTokens)

	resp, err := svc.ValidateToken(
		context.Background(),
		&authv1.ValidateTokenRequest{
			Token: "valid-token",
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, int32(-42), resp.UserId)
}
