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

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// LOGOUT
// ============================================================

func TestHandleLogout_Success_Cookie(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}

	tokenManager.GetSessionIDFromAccessTokenFunc = func(token string) (string, error) {
		return "session-A", nil
	}

	tokenManager.ClearAuthCookiesFunc = func(ctx *gin.Context) {}

	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.LogoutFunc = func(
		ctx context.Context,
		req *authv1.LogoutRequest,
	) (*authv1.LogoutResponse, error) {
		assert.Equal(t, "session-A", req.SessionId)
		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)

	req.AddCookie(&http.Cookie{
		Name:  "access_token",
		Value: "Bearer user42_sessionA_token",
	})

	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: "refresh-token",
	})

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestHandleLogout_Success_BearerHeader(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}
	tokenManager.GetSessionIDFromAccessTokenFunc = func(token string) (string, error) {
		return "session-A", nil
	}

	tokenManager.ClearAuthCookiesFunc = func(ctx *gin.Context) {}
	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.LogoutFunc = func(
		ctx context.Context,
		req *authv1.LogoutRequest,
	) (*authv1.LogoutResponse, error) {
		assert.Equal(t, "session-A", req.SessionId)
		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)

	req.Header.Set(
		"Authorization",
		"Bearer user42_sessionA_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestHandleLogout_CookieTakesPrecedence(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}

	tokenManager.GetSessionIDFromAccessTokenFunc = func(token string) (string, error) {
		return "session-A", nil
	}

	tokenManager.ClearAuthCookiesFunc = func(c *gin.Context) {}

	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.LogoutFunc = func(
		ctx context.Context,
		req *authv1.LogoutRequest,
	) (*authv1.LogoutResponse, error) {
		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)

	req.AddCookie(&http.Cookie{
		Name:  "access_token",
		Value: "Bearer user42_sessionA_token",
	})

	req.Header.Set(
		"Authorization",
		"Bearer user42_sessionB_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestHandleLogout_NoToken(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}

	tokenManager.GetSessionIDFromAccessTokenFunc = func(token string) (string, error) {
		assert.Empty(t, token)
		return "", errors.New("access token missing")
	}

	tokenManager.ClearAuthCookiesFunc = func(c *gin.Context) {}

	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.LogoutFunc = func(
		ctx context.Context,
		req *authv1.LogoutRequest,
	) (*authv1.LogoutResponse, error) {
		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleLogout_TokenParseError(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}

	tokenManager.GetSessionIDFromAccessTokenFunc = func(token string) (string, error) {
		return "", entities.ErrUnauthorized
	}

	tokenManager.ClearAuthCookiesFunc = func(c *gin.Context) {}

	router := setupRouter(t, mockSvc, tokenManager)

	called := false

	mockSvc.LogoutFunc = func(
		ctx context.Context,
		req *authv1.LogoutRequest,
	) (*authv1.LogoutResponse, error) {
		called = true
		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)

	req.Header.Set(
		"Authorization",
		"Bearer invalid-token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.True(t, called)
}

func TestHandleLogout_ServiceError(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}

	tokenManager.GetSessionIDFromAccessTokenFunc = func(token string) (string, error) {

		return "session-A", nil
	}

	tokenManager.ClearAuthCookiesFunc = func(c *gin.Context) {}

	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.LogoutFunc = func(
		ctx context.Context,
		req *authv1.LogoutRequest,
	) (*authv1.LogoutResponse, error) {
		assert.Equal(t, "session-A", req.SessionId)
		return nil, entities.ErrInternalServerError
	}

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)

	req.Header.Set(
		"Authorization",
		"Bearer user42_sessionA_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// ============================================================
// LOGOUT ALL
// ============================================================

func TestHandleLogoutAll_Success(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}

	tokenManager.GetUserIDFromAccessTokenFunc = func(token string) (string, error) {
		assert.Equal(t, "user42_sessionA_token", token)
		return "42", nil
	}

	tokenManager.ClearAuthCookiesFunc = func(c *gin.Context) {}

	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.LogoutAllFunc = func(
		ctx context.Context,
		req *authv1.LogoutAllRequest,
	) (*authv1.LogoutResponse, error) {
		assert.Equal(t, int32(42), req.UserId)
		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/logout/all", nil)

	req.Header.Set(
		"Authorization",
		"Bearer user42_sessionA_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestHandleLogoutAll_NoToken(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}

	tokenManager.GetUserIDFromAccessTokenFunc = func(token string) (string, error) {
		assert.Empty(t, token)
		return "", errors.New("access token missing")
	}

	tokenManager.ClearAuthCookiesFunc = func(c *gin.Context) {}

	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.LogoutAllFunc = func(
		ctx context.Context,
		req *authv1.LogoutAllRequest,
	) (*authv1.LogoutResponse, error) {

		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/logout/all", nil)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleLogoutAll_TokenParseError(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}

	tokenManager.GetUserIDFromAccessTokenFunc = func(token string) (string, error) {
		return "", errors.New("invalid access token")
	}

	tokenManager.ClearAuthCookiesFunc = func(c *gin.Context) {}

	router := setupRouter(t, mockSvc, tokenManager)

	called := false

	mockSvc.LogoutAllFunc = func(
		ctx context.Context,
		req *authv1.LogoutAllRequest,
	) (*authv1.LogoutResponse, error) {
		called = true
		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/logout/all", nil)

	req.Header.Set(
		"Authorization",
		"Bearer invalid-token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, called)
}

func TestHandleLogoutAll_InvalidUserID(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}

	tokenManager.GetUserIDFromAccessTokenFunc = func(token string) (string, error) {
		return "not-a-number", nil
	}

	tokenManager.ClearAuthCookiesFunc = func(c *gin.Context) {}

	router := setupRouter(t, mockSvc, tokenManager)

	called := false

	mockSvc.LogoutAllFunc = func(
		ctx context.Context,
		req *authv1.LogoutAllRequest,
	) (*authv1.LogoutResponse, error) {
		called = true
		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/logout/all", nil)

	req.Header.Set(
		"Authorization",
		"Bearer some-token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, called)
}

func TestHandleLogoutAll_ServiceError(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}

	tokenManager.GetUserIDFromAccessTokenFunc = func(token string) (string, error) {
		return "42", nil
	}

	tokenManager.ClearAuthCookiesFunc = func(c *gin.Context) {}

	router := setupRouter(t, mockSvc, tokenManager)

	mockSvc.LogoutAllFunc = func(
		ctx context.Context,
		req *authv1.LogoutAllRequest,
	) (*authv1.LogoutResponse, error) {
		assert.Equal(t, int32(42), req.UserId)
		return nil, errors.New("logout all service unavailable")
	}

	req := httptest.NewRequest(http.MethodPost, "/logout/all", nil)

	req.Header.Set(
		"Authorization",
		"Bearer user42_sessionA_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleLogoutAll_PassesAuthenticatedUser(t *testing.T) {
	mockSvc := &mocks.MockPublicIdentityService{}
	tokenManager := &mocks.MockTokenManager{}

	tokenManager.GetUserIDFromAccessTokenFunc = func(token string) (string, error) {
		assert.Equal(t, "user42_sessionA_token", token)
		return "42", nil
	}

	tokenManager.ClearAuthCookiesFunc = func(c *gin.Context) {}

	router := setupRouter(t, mockSvc, tokenManager)

	var receivedUserID int32

	mockSvc.LogoutAllFunc = func(
		ctx context.Context,
		req *authv1.LogoutAllRequest,
	) (*authv1.LogoutResponse, error) {
		receivedUserID = req.UserId
		return &authv1.LogoutResponse{}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/logout/all", nil)

	req.Header.Set(
		"Authorization",
		"Bearer user42_sessionA_token",
	)

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, int32(42), receivedUserID)
}
