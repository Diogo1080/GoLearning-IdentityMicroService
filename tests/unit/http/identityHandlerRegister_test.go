package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/tests/mocks"

	"github.com/go-jose/go-jose/v4/testutils/require"
	"github.com/stretchr/testify/assert"
)

// ============================================================
// REGISTER
// ============================================================

func TestHandleRegister_Success(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	called := false

	mockSvc.RegisterFunc = func(
		ctx context.Context,
		req *authv1.RegisterRequest,
	) (*authv1.RegisterResponse, error) {
		called = true

		assert.Equal(t, "john", req.Username)
		assert.Equal(t, "john@example.com", req.Email)
		assert.Equal(t, "Password123!", req.Password)
		assert.Equal(t, "1990-01-01", req.Birthdate)

		return &authv1.RegisterResponse{
			Success: true,
			UserId:  42,
		}, nil
	}

	body := map[string]string{
		"username":  "john",
		"password":  "Password123!",
		"email":     "john@example.com",
		"birthdate": "1990-01-01",
	}

	req := jsonRequest(t, http.MethodPost, "/register", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.True(t, called)

	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

	assert.Equal(t, "user registered successfully", response["message"])
	assert.Equal(t, float64(42), response["user_id"])
}

func TestHandleRegister_InvalidJSON(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	req := httptest.NewRequest(
		http.MethodPost,
		"/register",
		bytes.NewBufferString(`{"username":`),
	)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRegister_MissingUsername(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	body := map[string]string{
		"password":  "Password123!",
		"email":     "john@example.com",
		"birthdate": "1990-01-01",
	}

	req := jsonRequest(t, http.MethodPost, "/register", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRegister_InvalidUsername(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	body := map[string]string{
		"username":  "ab",
		"password":  "Password123!",
		"email":     "john@example.com",
		"birthdate": "1990-01-01",
	}

	req := jsonRequest(t, http.MethodPost, "/register", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRegister_InvalidEmail(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	body := map[string]string{
		"username":  "john",
		"password":  "Password123!",
		"email":     "not-an-email",
		"birthdate": "1990-01-01",
	}

	req := jsonRequest(t, http.MethodPost, "/register", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRegister_InvalidPassword(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	body := map[string]string{
		"username":  "john",
		"password":  "123",
		"email":     "john@example.com",
		"birthdate": "1990-01-01",
	}

	req := jsonRequest(t, http.MethodPost, "/register", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRegister_InvalidBirthdate(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	body := map[string]string{
		"username":  "john",
		"password":  "Password123!",
		"email":     "john@example.com",
		"birthdate": "not-a-date",
	}

	req := jsonRequest(t, http.MethodPost, "/register", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRegister_AlreadyExists(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.RegisterFunc = func(
		ctx context.Context,
		req *authv1.RegisterRequest,
	) (*authv1.RegisterResponse, error) {
		return nil, domain.ErrConflict
	}

	body := map[string]string{
		"username":  "existing",
		"password":  "Password123!",
		"email":     "existing@example.com",
		"birthdate": "1990-01-01",
	}

	req := jsonRequest(t, http.MethodPost, "/register", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestHandleRegister_ServiceError(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.RegisterFunc = func(
		ctx context.Context,
		req *authv1.RegisterRequest,
	) (*authv1.RegisterResponse, error) {
		return nil, errors.New("database unavailable")
	}

	body := map[string]string{
		"username":  "john",
		"password":  "Password123!",
		"email":     "john@example.com",
		"birthdate": "1990-01-01",
	}

	req := jsonRequest(t, http.MethodPost, "/register", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
