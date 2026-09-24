package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/tests/mocks"

	"github.com/go-openapi/testify/v2/require"
	"github.com/stretchr/testify/assert"
)

// ============================================================
// DELETE USER
// ============================================================

func TestHandleDeleteUser_Success(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	called := false

	mockSvc.DeleteUserFunc = func(
		ctx context.Context,
		req *authv1.DeleteUserRequest,
	) (*authv1.DeleteUserResponse, error) {
		called = true
		assert.Equal(t, int32(42), req.UserId)

		return &authv1.DeleteUserResponse{
			Success: true,
		}, nil
	}

	req := authenticatedRequest(
		t,
		http.MethodDelete,
		"/users/42",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, called)

	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

	assert.Equal(t, "Success", response["message"])
}

func TestHandleDeleteUser_NoToken(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	req := httptest.NewRequest(
		http.MethodDelete,
		"/users/42",
		nil,
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleDeleteUser_InvalidID(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	req := authenticatedRequest(t,
		http.MethodDelete,
		"/users/invalid",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleDeleteUser_IDMismatch(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	called := false

	mockSvc.DeleteUserFunc = func(
		ctx context.Context,
		req *authv1.DeleteUserRequest,
	) (*authv1.DeleteUserResponse, error) {
		called = true
		return &authv1.DeleteUserResponse{Success: true}, nil
	}

	// JWT user = 42
	// URL user = 99
	req := authenticatedRequest(t,
		http.MethodDelete,
		"/users/99",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, called, "service must not be called for another user")
}

func TestHandleDeleteUser_JWTUser99(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.DeleteUserFunc = func(
		ctx context.Context,
		req *authv1.DeleteUserRequest,
	) (*authv1.DeleteUserResponse, error) {
		assert.Equal(t, int32(99), req.UserId)

		return &authv1.DeleteUserResponse{
			Success: true,
		}, nil
	}

	req := authenticatedRequest(t,
		http.MethodDelete,
		"/users/99",
		nil,
		"user99_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleDeleteUser_NotFound(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.DeleteUserFunc = func(
		ctx context.Context,
		req *authv1.DeleteUserRequest,
	) (*authv1.DeleteUserResponse, error) {
		return nil, domain.ErrNotFound
	}

	req := authenticatedRequest(t,
		http.MethodDelete,
		"/users/42",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleDeleteUser_ServiceError(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.DeleteUserFunc = func(
		ctx context.Context,
		req *authv1.DeleteUserRequest,
	) (*authv1.DeleteUserResponse, error) {
		return nil, errors.New("database unavailable")
	}

	req := authenticatedRequest(t,
		http.MethodDelete,
		"/users/42",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
