package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/service"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/tokens"
	middleware "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http/middleware"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/tests/mocks"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func middlewareRouter(t *testing.T, tokenManager *mocks.MockTokenManager) *gin.Engine {
	t.Helper()

	identityService := service.NewInternalIdentityService(
		&mocks.MockIdentityRepository{},
		tokenManager,
	)

	router := gin.New()
	router.Use(middleware.NewidentityMiddlewareBuilder(identityService).Build())
	router.GET("/protected", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	return router
}

func TestIdentityMiddleware_UsesBearerToken(t *testing.T) {
	var parsedToken string
	tokenManager := &mocks.MockTokenManager{
		ParseAccessFunc: func(token string) (*tokens.Claims, error) {
			parsedToken = token
			return &tokens.Claims{SessionID: "session-1", RegisteredClaims: jwt.RegisteredClaims{Subject: "42"}}, nil
		},
		ValidateTokenFunc: func(context.Context, *tokens.Claims) (bool, error) {
			return true, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()

	middlewareRouter(t, tokenManager).ServeHTTP(response, req)

	assert.Equal(t, http.StatusNoContent, response.Code)
	assert.Equal(t, "access-token", parsedToken)
}

func TestIdentityMiddleware_UsesCookieToken(t *testing.T) {
	var parsedToken string
	tokenManager := &mocks.MockTokenManager{
		ParseAccessFunc: func(token string) (*tokens.Claims, error) {
			parsedToken = token
			return &tokens.Claims{SessionID: "session-1", RegisteredClaims: jwt.RegisteredClaims{Subject: "42"}}, nil
		},
		ValidateTokenFunc: func(context.Context, *tokens.Claims) (bool, error) {
			return true, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "cookie-token"})
	response := httptest.NewRecorder()

	middlewareRouter(t, tokenManager).ServeHTTP(response, req)

	assert.Equal(t, http.StatusNoContent, response.Code)
	assert.Equal(t, "cookie-token", parsedToken)
}

func TestIdentityMiddleware_RejectsMissingToken(t *testing.T) {
	called := false
	tokenManager := &mocks.MockTokenManager{
		ParseAccessFunc: func(string) (*tokens.Claims, error) {
			called = true
			return nil, nil
		},
	}

	response := httptest.NewRecorder()
	middlewareRouter(t, tokenManager).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/protected", nil))

	assert.Equal(t, http.StatusUnauthorized, response.Code)
	assert.False(t, called)
}

func TestIdentityMiddleware_RejectsInvalidToken(t *testing.T) {
	tokenManager := &mocks.MockTokenManager{
		ParseAccessFunc: func(string) (*tokens.Claims, error) {
			return nil, domain.ErrUnauthorized
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	response := httptest.NewRecorder()

	middlewareRouter(t, tokenManager).ServeHTTP(response, req)

	assert.Equal(t, http.StatusUnauthorized, response.Code)
}

func TestIdentityMiddleware_RejectsUnavailableAuthService(t *testing.T) {
	tokenManager := &mocks.MockTokenManager{
		ParseAccessFunc: func(string) (*tokens.Claims, error) {
			return &tokens.Claims{SessionID: "session-1", RegisteredClaims: jwt.RegisteredClaims{Subject: "42"}}, nil
		},
		ValidateTokenFunc: func(context.Context, *tokens.Claims) (bool, error) {
			return false, errors.New("auth service unavailable")
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()

	middlewareRouter(t, tokenManager).ServeHTTP(response, req)

	assert.Equal(t, http.StatusUnauthorized, response.Code)
}

func TestIdentityMiddleware_PropagatesCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var receivedContext context.Context
	tokenManager := &mocks.MockTokenManager{
		ParseAccessFunc: func(string) (*tokens.Claims, error) {
			return &tokens.Claims{SessionID: "session-1", RegisteredClaims: jwt.RegisteredClaims{Subject: "42"}}, nil
		},
		ValidateTokenFunc: func(ctx context.Context, _ *tokens.Claims) (bool, error) {
			receivedContext = ctx
			return false, ctx.Err()
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()

	middlewareRouter(t, tokenManager).ServeHTTP(response, req)

	assert.Equal(t, http.StatusUnauthorized, response.Code)
	assert.ErrorIs(t, receivedContext.Err(), context.Canceled)
}
