package tests

import (
	"bytes"
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
// UPDATE USER
// ============================================================

func TestHandleUpdateUser_Success(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.UpdateUserFunc = func(
		ctx context.Context,
		req *authv1.UpdateUserRequest,
	) (*authv1.UpdateUserResponse, error) {
		assert.Equal(t, int32(42), req.UserId)
		assert.Equal(t, "newusername", req.Username)
		assert.Equal(t, "new@email.com", req.Email)
		assert.Equal(t, "1991-01-01", req.Birthdate)

		return &authv1.UpdateUserResponse{
			Success: true,
		}, nil
	}

	body := map[string]string{
		"username":  "newusername",
		"email":     "new@email.com",
		"birthdate": "1991-01-01",
	}

	req := authenticatedRequest(t,
		http.MethodPut,
		"/users",
		body,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleUpdateUser_NoToken(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	body := map[string]string{
		"username": "newusername",
		"email":    "new@email.com",
	}

	req := jsonRequest(t, http.MethodPut, "/users", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleUpdateUser_InvalidJSON(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	req := httptest.NewRequest(
		http.MethodPut,
		"/users",
		bytes.NewBufferString(`{"username":`),
	)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid_jwt_token")

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleUpdateUser_UserIDComesFromJWT(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.UpdateUserFunc = func(
		ctx context.Context,
		req *authv1.UpdateUserRequest,
	) (*authv1.UpdateUserResponse, error) {
		assert.Equal(t, int32(42), req.UserId)
		return &authv1.UpdateUserResponse{Success: true}, nil
	}

	body := map[string]interface{}{
		"user_id":   999,
		"username":  "john",
		"email":     "john@example.com",
		"birthdate": "1990-01-01",
	}

	req := authenticatedRequest(t,
		http.MethodPut,
		"/users",
		body,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleUpdateUser_NotFound(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.UpdateUserFunc = func(
		ctx context.Context,
		req *authv1.UpdateUserRequest,
	) (*authv1.UpdateUserResponse, error) {
		return nil, domain.ErrNotFound
	}

	body := map[string]string{
		"username":  "john",
		"email":     "john@example.com",
		"birthdate": "1990-01-01",
	}

	req := authenticatedRequest(t,
		http.MethodPut,
		"/users",
		body,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleUpdateUser_ServiceError(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.UpdateUserFunc = func(
		ctx context.Context,
		req *authv1.UpdateUserRequest,
	) (*authv1.UpdateUserResponse, error) {
		return nil, errors.New("database unavailable")
	}

	body := map[string]string{
		"username":  "john",
		"email":     "john@example.com",
		"birthdate": "1990-01-01",
	}

	req := authenticatedRequest(t,
		http.MethodPut,
		"/users",
		body,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
