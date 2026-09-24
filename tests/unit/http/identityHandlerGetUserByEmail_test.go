package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/tests/mocks"

	"github.com/stretchr/testify/assert"
)

// ============================================================
// GET USER BY EMAIL
// ============================================================

func TestHandleGetUserByEmail_Success(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

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

	req := authenticatedRequest(t,
		http.MethodGet,
		"/users/email/john@example.com",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleGetUserByEmail_NoToken(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

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
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	req := authenticatedRequest(t,
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
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

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

	req := authenticatedRequest(t,
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
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.GetUserByEmailFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		return nil, domain.ErrNotFound
	}

	req := authenticatedRequest(t,
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
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.GetUserByEmailFunc = func(
		ctx context.Context,
		req *authv1.GetUserRequest,
	) (*authv1.GetUserResponse, error) {
		return nil, errors.New("database unavailable")
	}

	req := authenticatedRequest(t,
		http.MethodGet,
		"/users/email/john@example.com",
		nil,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
