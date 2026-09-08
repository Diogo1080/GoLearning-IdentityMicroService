package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/tests/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// LOGIN
// ============================================================

func TestHandleLogin_Success(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.LoginFunc = func(
		ctx context.Context,
		req *authv1.LoginRequest,
	) (*authv1.LoginResponse, error) {
		assert.Equal(t, "test@example.com", req.Usernameoremail)
		assert.Equal(t, "password123", req.Password)

		return &authv1.LoginResponse{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
		}, nil
	}

	req := jsonRequest(t,
		http.MethodPost,
		"/login",
		map[string]string{
			"usernameoremail": "test@example.com",
			"password":        "password123",
		},
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}

	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "access-token", response["access_token"])
	assert.Equal(t, "refresh-token", response["refresh_token"])
}

func TestHandleLogin_ServiceError(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.LoginFunc = func(
		ctx context.Context,
		req *authv1.LoginRequest,
	) (*authv1.LoginResponse, error) {
		return nil, assert.AnError
	}

	req := jsonRequest(t,
		http.MethodPost,
		"/login",
		map[string]string{
			"usernameoremail": "test@example.com",
			"password":        "password123",
		},
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(
		t,
		http.StatusServiceUnavailable,
		w.Code,
	)
}

func TestHandleLogin_InvalidRequest(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	called := false

	mockSvc.LoginFunc = func(
		ctx context.Context,
		req *authv1.LoginRequest,
	) (*authv1.LoginResponse, error) {
		called = true

		return &authv1.LoginResponse{}, nil
	}

	req := jsonRequest(t,
		http.MethodPost,
		"/login",
		map[string]string{
			"usernameoremail": "test@example.com",
			// Missing password.
		},
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
	assert.False(t, called)
}

func TestHandleLogin_CallsServiceWithCorrectCredentials(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	var receivedRequest *authv1.LoginRequest

	mockSvc.LoginFunc = func(
		ctx context.Context,
		req *authv1.LoginRequest,
	) (*authv1.LoginResponse, error) {
		receivedRequest = req

		return &authv1.LoginResponse{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
		}, nil
	}

	req := jsonRequest(t,
		http.MethodPost,
		"/login",
		map[string]string{
			"usernameoremail": "john@example.com",
			"password":        "secret123",
		},
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, receivedRequest)

	assert.Equal(
		t,
		"john@example.com",
		receivedRequest.Usernameoremail,
	)

	assert.Equal(
		t,
		"secret123",
		receivedRequest.Password,
	)
}

func TestHandleLogin_SetsAuthCookies(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.LoginFunc = func(
		ctx context.Context,
		req *authv1.LoginRequest,
	) (*authv1.LoginResponse, error) {
		return &authv1.LoginResponse{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
		}, nil
	}

	req := jsonRequest(t,
		http.MethodPost,
		"/login",
		map[string]string{
			"usernameoremail": "test@example.com",
			"password":        "password123",
		},
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

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

	assert.Equal(
		t,
		"access-token",
		accessCookie.Value,
	)

	assert.Equal(
		t,
		"refresh-token",
		refreshCookie.Value,
	)

	assert.True(t, accessCookie.HttpOnly)
	assert.True(t, refreshCookie.HttpOnly)

	assert.True(
		t,
		accessCookie.Secure,
	)

	assert.True(
		t,
		refreshCookie.Secure,
	)
}

func TestHandleLogin_DoesNotCallServiceWhenRequestIsInvalid(
	t *testing.T,
) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	router := setupRouter(t, mockSvc, tokenManager)

	called := false

	mockSvc.LoginFunc = func(
		ctx context.Context,
		req *authv1.LoginRequest,
	) (*authv1.LoginResponse, error) {
		called = true

		return &authv1.LoginResponse{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
		}, nil
	}

	req := jsonRequest(t,
		http.MethodPost,
		"/login",
		map[string]string{},
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
	assert.False(t, called)
}
