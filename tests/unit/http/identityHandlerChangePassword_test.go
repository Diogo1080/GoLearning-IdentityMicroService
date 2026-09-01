package tests

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"GoLearning-IdentityMicroService/tests/mocks"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================================================
// CHANGE PASSWORD
// ============================================================

func TestHandleUpdatePassword_Success(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.ChangePasswordFunc = func(
		ctx context.Context,
		req *authv1.ChangePasswordRequest,
	) (*authv1.ChangePasswordResponse, error) {
		assert.Equal(t, int32(42), req.UserId)
		assert.Equal(t, "OldPassword123!", req.CurrentPassword)
		assert.Equal(t, "NewPassword456!", req.NewPassword)

		return &authv1.ChangePasswordResponse{
			Success: true,
		}, nil
	}

	body := map[string]string{
		"current_password": "OldPassword123!",
		"new_password":     "NewPassword456!",
	}

	req := authenticatedRequest(
		http.MethodPatch,
		"/password",
		body,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleUpdatePassword_NoToken(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	body := map[string]string{
		"current_password": "OldPassword123!",
		"new_password":     "NewPassword456!",
	}

	req := jsonRequest(
		http.MethodPatch,
		"/password",
		body,
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleUpdatePassword_InvalidJSON(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	req := httptest.NewRequest(
		http.MethodPatch,
		"/password",
		bytes.NewBufferString(`{"current_password":`),
	)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid_jwt_token")

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleUpdatePassword_UserIDComesFromJWT(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.ChangePasswordFunc = func(
		ctx context.Context,
		req *authv1.ChangePasswordRequest,
	) (*authv1.ChangePasswordResponse, error) {
		assert.Equal(t, int32(42), req.UserId)
		return &authv1.ChangePasswordResponse{Success: true}, nil
	}

	body := map[string]interface{}{
		"user_id":          999,
		"current_password": "OldPassword123!",
		"new_password":     "NewPassword456!",
	}

	req := authenticatedRequest(
		http.MethodPatch,
		"/password",
		body,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleUpdatePassword_NotFound(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.ChangePasswordFunc = func(
		ctx context.Context,
		req *authv1.ChangePasswordRequest,
	) (*authv1.ChangePasswordResponse, error) {
		return nil, entities.ErrNotFound
	}

	body := map[string]string{
		"current_password": "OldPassword123!",
		"new_password":     "NewPassword456!",
	}

	req := authenticatedRequest(
		http.MethodPatch,
		"/password",
		body,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleUpdatePassword_ServiceError(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.ChangePasswordFunc = func(
		ctx context.Context,
		req *authv1.ChangePasswordRequest,
	) (*authv1.ChangePasswordResponse, error) {
		return nil, errors.New("database unavailable")
	}

	body := map[string]string{
		"current_password": "OldPassword123!",
		"new_password":     "NewPassword456!",
	}

	req := authenticatedRequest(
		http.MethodPatch,
		"/password",
		body,
		"valid_jwt_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
