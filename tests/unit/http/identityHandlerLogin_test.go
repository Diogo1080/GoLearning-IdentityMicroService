package tests

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"GoLearning-IdentityMicroService/tests/mocks"
	"bytes"
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
// LOGIN
// ============================================================

func TestHandleLogin_Success(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.LoginFunc = func(
		ctx context.Context,
		req *authv1.LoginRequest,
	) (*authv1.LoginResponse, error) {
		assert.Equal(t, "john", req.Usernameoremail)
		assert.Equal(t, "Password123!", req.Password)

		return &authv1.LoginResponse{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			UserId:       42,
			Message:      "login successful",
		}, nil
	}

	body := map[string]string{
		"username": "john",
		"password": "Password123!",
	}

	req := jsonRequest(http.MethodPost, "/login", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

	assert.Equal(t, "access-token", response["access_token"])
	assert.Equal(t, "refresh-token", response["refresh_token"])
	assert.Equal(t, float64(42), response["user_id"])
	assert.Equal(t, "login successful", response["message"])

	cookies := w.Result().Cookies()

	var accessCookie *http.Cookie
	var refreshCookie *http.Cookie

	for _, cookie := range cookies {
		switch cookie.Name {
		case "access_token":
			accessCookie = cookie
		case "refresh_token":
			refreshCookie = cookie
		}
	}

	require.NotNil(t, accessCookie)
	require.NotNil(t, refreshCookie)

	assert.Equal(t, "access-token", accessCookie.Value)
	assert.Equal(t, "refresh-token", refreshCookie.Value)

	assert.True(t, accessCookie.HttpOnly)
	assert.True(t, refreshCookie.HttpOnly)

	assert.Equal(t, "/", accessCookie.Path)
	assert.Equal(t, "/", refreshCookie.Path)
}

func TestHandleLogin_InvalidJSON(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	req := httptest.NewRequest(
		http.MethodPost,
		"/login",
		bytes.NewBufferString(`{"username":`),
	)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLogin_MissingUsername(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	body := map[string]string{
		"password": "Password123!",
	}

	req := jsonRequest(http.MethodPost, "/login", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLogin_MissingPassword(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	body := map[string]string{
		"username": "john",
	}

	req := jsonRequest(http.MethodPost, "/login", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLogin_BadData(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.LoginFunc = func(
		ctx context.Context,
		req *authv1.LoginRequest,
	) (*authv1.LoginResponse, error) {
		return nil, entities.ErrBadData
	}

	body := map[string]string{
		"username": "john",
		"password": "Password123!",
	}

	req := jsonRequest(http.MethodPost, "/login", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLogin_NotFound(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.LoginFunc = func(
		ctx context.Context,
		req *authv1.LoginRequest,
	) (*authv1.LoginResponse, error) {
		return nil, entities.ErrNotFound
	}

	body := map[string]string{
		"username": "unknown",
		"password": "Password123!",
	}

	req := jsonRequest(http.MethodPost, "/login", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleLogin_Unauthorized(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.LoginFunc = func(
		ctx context.Context,
		req *authv1.LoginRequest,
	) (*authv1.LoginResponse, error) {
		return nil, entities.ErrUnauthorized
	}

	body := map[string]string{
		"username": "john",
		"password": "WrongPassword",
	}

	req := jsonRequest(http.MethodPost, "/login", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleLogin_ServiceError(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.LoginFunc = func(
		ctx context.Context,
		req *authv1.LoginRequest,
	) (*authv1.LoginResponse, error) {
		return nil, errors.New("database unavailable")
	}

	body := map[string]string{
		"username": "john",
		"password": "Password123!",
	}

	req := jsonRequest(http.MethodPost, "/login", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleLogin_NilResponse(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.LoginFunc = func(
		ctx context.Context,
		req *authv1.LoginRequest,
	) (*authv1.LoginResponse, error) {
		return nil, nil
	}

	body := map[string]string{
		"username": "john",
		"password": "Password123!",
	}

	req := jsonRequest(http.MethodPost, "/login", body)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
