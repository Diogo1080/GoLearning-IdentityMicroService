package tests

import (
	"context"
	"errors"
	"testing"

	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"GoLearning-IdentityMicroService/internal/tokens"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// LOGIN
// ============================================================

func TestPublicIdentityService_Login_Success_Email(t *testing.T) {
	repo, mockTokens, svc := newPublicIdentityService(t)

	user := testUser()

	repo.On("GetUserByEmail", testEmail).Return(user, nil)

	mockTokens.IssueTokensFunc = func(ctx context.Context, userID string) (*tokens.Tokens, error) {
		assert.Equal(t, "42", userID)
		return &tokens.Tokens{
			Access:  "test-access-token",
			Refresh: "test-refresh-token",
		}, nil
	}

	resp, err := svc.Login(
		context.Background(),
		&authv1.LoginRequest{
			Usernameoremail: testEmail,
			Password:        testPassword,
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, int32(testUserId), resp.UserId)
	assert.Equal(t, "test-access-token", resp.AccessToken)
	assert.Equal(t, "test-refresh-token", resp.RefreshToken)
	assert.Equal(t, "login successful", resp.Message)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_Login_Success_Username(t *testing.T) {
	repo, mockTokens, svc := newPublicIdentityService(t)

	user := testUser()

	repo.On("GetUserByUsername", testUsername).
		Return(user, nil)

	mockTokens.IssueTokensFunc = func(ctx context.Context, userID string) (*tokens.Tokens, error) {
		assert.Equal(t, "42", userID)

		return &tokens.Tokens{
			Access:  "test-access-token",
			Refresh: "test-refresh-token",
		}, nil
	}

	resp, err := svc.Login(
		context.Background(),
		&authv1.LoginRequest{
			Usernameoremail: testUsername,
			Password:        testPassword,
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, int32(testUserId), resp.UserId)
	assert.Equal(t, "test-access-token", resp.AccessToken)
	assert.Equal(t, "test-refresh-token", resp.RefreshToken)
	assert.Equal(t, "login successful", resp.Message)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_Login_InvalidUsernameOrEmail(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	resp, err := svc.Login(
		context.Background(),
		&authv1.LoginRequest{
			Usernameoremail: "",
			Password:        testPassword,
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrBadData)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_Login_UserNotFound(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	repo.On("GetUserByEmail", testEmail).
		Return(entities.User{}, entities.ErrNotFound)

	resp, err := svc.Login(
		context.Background(),
		&authv1.LoginRequest{
			Usernameoremail: testEmail,
			Password:        testPassword,
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrNotFound)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_Login_WrongPassword(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	repo.On("GetUserByEmail", testEmail).
		Return(testUser(), nil)

	resp, err := svc.Login(
		context.Background(),
		&authv1.LoginRequest{
			Usernameoremail: testEmail,
			Password:        "wrong-password",
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrUnauthorized)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_Login_TokenIssuanceError(t *testing.T) {
	repo, mockTokens, svc := newPublicIdentityService(t)

	repo.On("GetUserByEmail", testEmail).
		Return(testUser(), nil)

	issueErr := errors.New("failed to issue tokens")

	mockTokens.IssueTokensFunc = func(
		ctx context.Context,
		userID string,
	) (*tokens.Tokens, error) {
		assert.Equal(t, "42", userID)

		return nil, issueErr
	}

	resp, err := svc.Login(
		context.Background(),
		&authv1.LoginRequest{
			Usernameoremail: testEmail,
			Password:        testPassword,
		},
	)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, entities.ErrInternalServerError)

	repo.AssertExpectations(t)
}
