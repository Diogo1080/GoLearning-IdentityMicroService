package tests

import (
	"context"
	"testing"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"

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
		Return(domain.User{}, domain.ErrNotFound)

	resp, err := svc.GetUserByUsername(
		context.Background(),
		&authv1.GetUserRequest{
			Username: testUsername,
		},
	)

	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrNotFound)
	assert.NotNil(t, resp)

	repo.AssertExpectations(t)
}
