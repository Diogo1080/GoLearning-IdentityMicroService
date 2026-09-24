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
// GET USER BY ID
// ============================================================

func TestHandleGetUserByID_Success(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.GetUserByIDFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		assert.Equal(t, int32(42), req.Id)

		return &authv1.GetUserResponse{
			Id:       42,
			Username: "john",
			Email:    "john@example.com",
		}, nil
	}

	req := authenticatedRequest(t,
		http.MethodGet,
		"/users/42",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response authv1.GetUserResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

	assert.Equal(t, int32(42), response.Id)
	assert.Equal(t, "john", response.Username)
	assert.Equal(t, "john@example.com", response.Email)
}

func TestHandleGetUserByID_NoToken(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	req := httptest.NewRequest(
		http.MethodGet,
		"/users/42",
		nil,
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleGetUserByID_InvalidID(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	req := authenticatedRequest(t,
		http.MethodGet,
		"/users/invalid",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleGetUserByID_OtherUser(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	called := false

	mockSvc.GetUserByIDFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		called = true
		return nil, nil
	}

	req := authenticatedRequest(t,
		http.MethodGet,
		"/users/99",
		nil,
		"valid_jwt_token", // userID = 42
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, called, "service must not be called for another user")
}

func TestHandleGetUserByID_NotFound(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.GetUserByIDFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		return nil, domain.ErrNotFound
	}

	req := authenticatedRequest(t,
		http.MethodGet,
		"/users/42",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleGetUserByID_ServiceError(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.GetUserByIDFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		return nil, errors.New("database unavailable")
	}

	req := authenticatedRequest(t,
		http.MethodGet,
		"/users/42",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleGetCurrentUser_UsesAuthenticatedUserID(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.GetUserByIDFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		assert.Equal(t, int32(42), req.Id)

		return &authv1.GetUserResponse{Id: 42, Username: "john"}, nil
	}

	req := authenticatedRequest(t,
		http.MethodGet,
		"/users/me",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
