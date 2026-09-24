package tests

import (
	"context"
	"testing"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"

	"github.com/go-openapi/testify/v2/require"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// ============================================================
// DELETE USER
// ============================================================

func TestPublicIdentityService_DeleteUser_Success(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	repo.On("GetUserByID", testUserId).
		Return(testUser(), nil)

	repo.On("DeleteUser", testUserId).
		Return(nil)

	resp, err := svc.DeleteUser(
		context.Background(),
		&authv1.DeleteUserRequest{
			UserId: int32(testUserId),
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Success)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_DeleteUser_UserNotFound(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	repo.On("GetUserByID", testUserId).
		Return(domain.User{}, domain.ErrNotFound)

	resp, err := svc.DeleteUser(
		context.Background(),
		&authv1.DeleteUserRequest{
			UserId: int32(testUserId),
		},
	)

	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrNotFound)
	assert.False(t, resp.Success)

	repo.AssertExpectations(t)
	repo.AssertNotCalled(t, "DeleteUser", mock.Anything)
}

func TestPublicIdentityService_DeleteUser_DeleteError(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	repo.On("GetUserByID", testUserId).
		Return(testUser(), nil)

	repo.On("DeleteUser", testUserId).
		Return(assert.AnError)

	resp, err := svc.DeleteUser(
		context.Background(),
		&authv1.DeleteUserRequest{
			UserId: int32(testUserId),
		},
	)

	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
	assert.False(t, resp.Success)

	repo.AssertExpectations(t)
}
