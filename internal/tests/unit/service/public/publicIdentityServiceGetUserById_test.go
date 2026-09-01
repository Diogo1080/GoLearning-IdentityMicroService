package tests

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"context"
	"testing"

	"github.com/go-openapi/testify/v2/require"
	"github.com/stretchr/testify/assert"
)

// ============================================================
// GET USER BY ID
// ============================================================

func TestPublicIdentityService_GetUserByID_Success(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	user := testUser()

	repo.On("GetUserByID", testUserId).
		Return(user, nil)

	resp, err := svc.GetUserByID(
		context.Background(),
		&authv1.GetUserRequest{
			Id: testUserId,
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, int32(testUserId), resp.Id)
	assert.Equal(t, testUsername, resp.Username)
	assert.Equal(t, testEmail, resp.Email)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_GetUserByID_NotFound(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	repo.On("GetUserByID", testUserId).
		Return(entities.User{}, entities.ErrNotFound)

	resp, err := svc.GetUserByID(
		context.Background(),
		&authv1.GetUserRequest{
			Id: testUserId,
		},
	)

	require.Error(t, err)

	assert.ErrorIs(t, err, entities.ErrNotFound)
	assert.NotNil(t, resp)

	repo.AssertExpectations(t)
}
