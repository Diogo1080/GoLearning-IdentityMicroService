package tests

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	"GoLearning-IdentityMicroService/internal/tests/mocks"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/testify/v2/require"
	"github.com/stretchr/testify/assert"
)

// ============================================================
// LOGOUT
// ============================================================

func TestHandleLogout_Success_Cookie(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.LogoutFunc = func(
		ctx context.Context,
		req *authv1.LogoutRequest,
	) (*authv1.LogoutResponse, error) {
		assert.Equal(t, "cookie-token", req.Token)

		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/logout",
		nil,
	)

	req.AddCookie(&http.Cookie{
		Name:  "access_token",
		Value: "cookie-token",
	})

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleLogout_Success_BearerHeader(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.LogoutFunc = func(
		ctx context.Context,
		req *authv1.LogoutRequest,
	) (*authv1.LogoutResponse, error) {
		assert.Equal(t, "header-token", req.Token)

		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/logout",
		nil,
	)

	req.Header.Set(
		"Authorization",
		"Bearer header-token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleLogout_CookieTakesPrecedence(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.LogoutFunc = func(
		ctx context.Context,
		req *authv1.LogoutRequest,
	) (*authv1.LogoutResponse, error) {
		assert.Equal(t, "cookie-token", req.Token)

		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/logout",
		nil,
	)

	req.AddCookie(&http.Cookie{
		Name:  "access_token",
		Value: "cookie-token",
	})

	req.Header.Set(
		"Authorization",
		"Bearer header-token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleLogout_NoToken(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	called := false

	mockSvc.LogoutFunc = func(
		ctx context.Context,
		req *authv1.LogoutRequest,
	) (*authv1.LogoutResponse, error) {
		called = true
		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/logout",
		nil,
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.False(t, called)
}

func TestHandleLogout_ServiceError(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.LogoutFunc = func(
		ctx context.Context,
		req *authv1.LogoutRequest,
	) (*authv1.LogoutResponse, error) {
		return nil, errors.New("logout service unavailable")
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/logout",
		nil,
	)

	req.Header.Set(
		"Authorization",
		"Bearer access-token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleLogout_ClearsCookies(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	router := setupRouter(mockSvc)

	mockSvc.LogoutFunc = func(
		ctx context.Context,
		req *authv1.LogoutRequest,
	) (*authv1.LogoutResponse, error) {
		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/logout",
		nil,
	)

	req.AddCookie(&http.Cookie{
		Name:  "access_token",
		Value: "access-token",
	})

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

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

	assert.Equal(t, "", accessCookie.Value)
	assert.Equal(t, "", refreshCookie.Value)

	assert.True(t, accessCookie.MaxAge < 0)
	assert.True(t, refreshCookie.MaxAge < 0)
}
