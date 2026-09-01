package tests

import (
	"GoLearning-IdentityMicroService/internal/tokens"
	"context"
	"os"
	"testing"

	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"

	"github.com/go-openapi/testify/v2/require"
	"github.com/stretchr/testify/assert"
)

// ============================================================
// LOGIN
// ============================================================

func TestPublicIdentityService_Login_Success_Email(t *testing.T) {
	os.Setenv("ACCESS_SECRET", "test-access-secret")
	os.Setenv("REFRESH_SECRET", "test-refresh-secret")
	repo, rdb, svc := newPublicIdentityService(t)

	user := testUser()

	repo.On("GetUserByEmail", testEmail).
		Return(user, nil)

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
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "login successful", resp.Message)

	// Verify access token is valid.
	accessClaims, err := tokens.ParseAccess(resp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "42", accessClaims.Subject)

	// Verify refresh token is valid.
	refreshClaims, err := tokens.ParseRefresh(resp.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, "42", refreshClaims.Subject)

	// Verify tokens were persisted.
	value, err := rdb.GetUserByJTI(
		context.Background(),
		"access:"+accessClaims.ID,
	)
	require.NoError(t, err)
	assert.Equal(t, "42", value)

	value, err = rdb.GetUserByJTI(
		context.Background(),
		"refresh:"+refreshClaims.ID,
	)
	require.NoError(t, err)
	assert.Equal(t, "42", value)

	repo.AssertExpectations(t)
}

func TestPublicIdentityService_Login_Success_Username(t *testing.T) {
	repo, _, svc := newPublicIdentityService(t)

	user := testUser()

	repo.On("GetUserByUsername", testUsername).
		Return(user, nil)

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
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)

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
