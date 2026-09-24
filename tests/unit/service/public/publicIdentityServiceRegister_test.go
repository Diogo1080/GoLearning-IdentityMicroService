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
// REGISTER
// ============================================================

func TestPublicIdentityService_Register_Success(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	createdUser := testUser()

	// Adapt these expectations to your MockIdentityRepository
	// implementation if it doesn't use testify/mock.
	repo.On("GetUserByEmail", testEmail).
		Return(domain.User{}, domain.ErrNotFound)

	repo.On("GetUserByUsername", testUsername).
		Return(domain.User{}, domain.ErrNotFound)

	repo.On("CreateUser", mock.AnythingOfType("domain.User")).
		Return(createdUser, nil)

	resp, err := svc.Register(
		context.Background(),
		&authv1.RegisterRequest{
			Username:  testUsername,
			Email:     testEmail,
			Password:  testPassword,
			Birthdate: "1995-01-01",
		},
	)

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Success)
	assert.Equal(t, int32(testUserId), resp.UserId)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_Register_EmailAlreadyExists(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	existingUser := testUser()

	repo.On("GetUserByEmail", testEmail).
		Return(existingUser, nil)

	resp, err := svc.Register(
		context.Background(),
		&authv1.RegisterRequest{
			Username:  testUsername,
			Email:     testEmail,
			Password:  testPassword,
			Birthdate: "1995-01-01",
		},
	)

	require.Error(t, err)

	assert.ErrorIs(t, err, domain.ErrConflict)
	assert.False(t, resp.Success)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_Register_UsernameAlreadyExists(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	repo.On("GetUserByEmail", testEmail).
		Return(domain.User{}, domain.ErrNotFound)

	repo.On("GetUserByUsername", testUsername).
		Return(testUser(), nil)

	resp, err := svc.Register(
		context.Background(),
		&authv1.RegisterRequest{
			Username:  testUsername,
			Email:     testEmail,
			Password:  testPassword,
			Birthdate: "1995-01-01",
		},
	)

	require.Error(t, err)

	assert.ErrorIs(t, err, domain.ErrConflict)
	assert.False(t, resp.Success)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_Register_CreateUserError(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	repo.On("GetUserByEmail", testEmail).
		Return(domain.User{}, domain.ErrNotFound)

	repo.On("GetUserByUsername", testUsername).
		Return(domain.User{}, domain.ErrNotFound)

	repo.On("CreateUser", mock.AnythingOfType("domain.User")).
		Return(domain.User{}, assert.AnError)

	resp, err := svc.Register(
		context.Background(),
		&authv1.RegisterRequest{
			Username:  testUsername,
			Email:     testEmail,
			Password:  testPassword,
			Birthdate: "1995-01-01",
		},
	)

	require.Error(t, err)

	assert.ErrorIs(t, err, domain.ErrInternal)
	assert.False(t, resp.Success)

	repo.AssertExpectations(t)
}
