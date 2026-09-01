package tests

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"context"
	"testing"

	"github.com/go-openapi/testify/v2/require"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// ============================================================
// CHANGE PASSWORD
// ============================================================

func TestPublicIdentityService_ChangePassword_Success(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	user := testUser()

	repo.On("GetUserByID", testUserId).
		Return(user, nil)

	repo.On(
		"UpdatePassword",
		testUserId,
		mock.MatchedBy(func(hash string) bool {
			return VerifyPassword("new-password", hash)
		}),
	).Return(nil)

	resp, err := svc.ChangePassword(
		context.Background(),
		&authv1.ChangePasswordRequest{
			UserId:          int32(testUserId),
			CurrentPassword: testPassword,
			NewPassword:     "new-password",
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Success)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_ChangePassword_UserNotFound(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	repo.On("GetUserByID", testUserId).
		Return(entities.User{}, entities.ErrNotFound)

	resp, err := svc.ChangePassword(
		context.Background(),
		&authv1.ChangePasswordRequest{
			UserId:          int32(testUserId),
			CurrentPassword: testPassword,
			NewPassword:     "new-password",
		},
	)

	require.Error(t, err)
	assert.ErrorIs(t, err, entities.ErrNotFound)
	assert.False(t, resp.Success)

	repo.AssertExpectations(t)
	repo.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything)
}

func TestPublicIdentityService_ChangePassword_WrongCurrentPassword(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	repo.On("GetUserByID", testUserId).
		Return(testUser(), nil)

	resp, err := svc.ChangePassword(
		context.Background(),
		&authv1.ChangePasswordRequest{
			UserId:          int32(testUserId),
			CurrentPassword: "wrong-password",
			NewPassword:     "new-password",
		},
	)

	require.Error(t, err)
	assert.ErrorIs(t, err, entities.ErrUnauthorized)
	assert.False(t, resp.Success)

	repo.AssertExpectations(t)
	repo.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything)
}

func TestPublicIdentityService_ChangePassword_UpdateError(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	user := testUser()

	repo.On("GetUserByID", testUserId).
		Return(user, nil)

	repo.On("UpdatePassword", testUserId, mock.Anything).
		Return(assert.AnError)

	resp, err := svc.ChangePassword(
		context.Background(),
		&authv1.ChangePasswordRequest{
			UserId:          int32(testUserId),
			CurrentPassword: testPassword,
			NewPassword:     "new-password",
		},
	)

	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
	assert.False(t, resp.Success)

	repo.AssertExpectations(t)
}
