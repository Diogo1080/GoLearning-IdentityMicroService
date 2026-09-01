package tests

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"GoLearning-IdentityMicroService/internal/tests/mocks"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/testify/v2/require"
	"github.com/stretchr/testify/assert"
)

// ============================================================
// GET USER BY ID
// ============================================================

func TestHandleGetUserByID_Success(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

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

	req := authenticatedRequest(
		http.MethodGet,
		"/users/42",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)

	var response authv1.GetUserResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

	assert.Equal(t, int32(42), response.Id)
	assert.Equal(t, "john", response.Username)
	assert.Equal(t, "john@example.com", response.Email)
}

func TestHandleGetUserByID_NoToken(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

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
	router := setupRouter(mockSvc)

	req := authenticatedRequest(
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
	router := setupRouter(mockSvc)

	called := false

	mockSvc.GetUserByIDFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		called = true
		return nil, nil
	}

	req := authenticatedRequest(
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
	router := setupRouter(mockSvc)

	mockSvc.GetUserByIDFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		return nil, entities.ErrNotFound
	}

	req := authenticatedRequest(
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
	router := setupRouter(mockSvc)

	mockSvc.GetUserByIDFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		return nil, errors.New("database unavailable")
	}

	req := authenticatedRequest(
		http.MethodGet,
		"/users/42",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
