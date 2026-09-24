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
// UPDATE USER
// ============================================================

func TestPublicIdentityService_UpdateUser_Success(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	user := testUser()

	repo.On("GetUserByID", testUserId).
		Return(user, nil)

	repo.On("UpdateUser", testUserId, mock.Anything).
		Return(nil)

	resp, err := svc.UpdateUser(
		context.Background(),
		&authv1.UpdateUserRequest{
			UserId:    int32(testUserId),
			Username:  "updatedUsername",
			Email:     "updated@example.com",
			Birthdate: "2000-01-01",
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Success)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_UpdateUser_UserNotFound(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	repo.On("GetUserByID", testUserId).
		Return(domain.User{}, domain.ErrNotFound)

	resp, err := svc.UpdateUser(
		context.Background(),
		&authv1.UpdateUserRequest{
			UserId:    int32(testUserId),
			Username:  "updatedUsername",
			Email:     "updated@example.com",
			Birthdate: "2000-01-01",
		},
	)

	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrNotFound)
	assert.False(t, resp.Success)

	repo.AssertExpectations(t)
	repo.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
}

func TestPublicIdentityService_UpdateUser_UpdateError(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	user := testUser()

	repo.On("GetUserByID", testUserId).
		Return(user, nil)

	repo.On("UpdateUser", testUserId, mock.Anything).
		Return(assert.AnError)

	resp, err := svc.UpdateUser(
		context.Background(),
		&authv1.UpdateUserRequest{
			UserId:    int32(testUserId),
			Username:  "updatedUsername",
			Email:     "updated@example.com",
			Birthdate: "2000-01-01",
		},
	)

	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
	assert.False(t, resp.Success)

	repo.AssertExpectations(t)
}
