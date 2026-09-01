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
// GET USER BY USERNAME
// ============================================================

func TestPublicIdentityService_GetUserByUsername_Success(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	user := testUser()

	repo.On("GetUserByUsername", testUsername).
		Return(user, nil)

	resp, err := svc.GetUserByUsername(
		context.Background(),
		&authv1.GetUserRequest{
			Username: testUsername,
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, int32(testUserId), resp.Id)
	assert.Equal(t, testUsername, resp.Username)
	assert.Equal(t, testEmail, resp.Email)
	assert.Equal(t, user.Birthday.String(), resp.Birthdate)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_GetUserByUsername_UserNotFound(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	repo.On("GetUserByUsername", testUsername).
		Return(entities.User{}, entities.ErrNotFound)

	resp, err := svc.GetUserByUsername(
		context.Background(),
		&authv1.GetUserRequest{
			Username: testUsername,
		},
	)

	require.Error(t, err)
	assert.ErrorIs(t, err, entities.ErrNotFound)
	assert.NotNil(t, resp)

	repo.AssertExpectations(t)
}
