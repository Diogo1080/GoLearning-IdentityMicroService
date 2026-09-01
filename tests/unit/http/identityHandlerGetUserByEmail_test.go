package tests

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"GoLearning-IdentityMicroService/tests/mocks"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================================================
// GET USER BY EMAIL
// ============================================================

func TestHandleGetUserByEmail_Success(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.GetUserByEmailFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		assert.Equal(t, "john@example.com", req.Email)

		return &authv1.GetUserResponse{
			Id:       42,
			Username: "john",
			Email:    "john@example.com",
		}, nil
	}

	req := authenticatedRequest(
		http.MethodGet,
		"/users/email/john@example.com",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
}

func TestHandleGetUserByEmail_NoToken(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	req := httptest.NewRequest(
		http.MethodGet,
		"/users/email/john@example.com",
		nil,
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleGetUserByEmail_InvalidEmail(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	req := authenticatedRequest(
		http.MethodGet,
		"/users/email/not-an-email",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleGetUserByEmail_OtherUser(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.GetUserByEmailFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		return &authv1.GetUserResponse{
			Id:       99,
			Username: "other",
			Email:    "other@example.com",
		}, nil
	}

	req := authenticatedRequest(
		http.MethodGet,
		"/users/email/other@example.com",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleGetUserByEmail_NotFound(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.GetUserByEmailFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		return nil, entities.ErrNotFound
	}

	req := authenticatedRequest(
		http.MethodGet,
		"/users/email/john@example.com",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleGetUserByEmail_ServiceError(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.GetUserByEmailFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		return nil, errors.New("database unavailable")
	}

	req := authenticatedRequest(
		http.MethodGet,
		"/users/email/john@example.com",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
