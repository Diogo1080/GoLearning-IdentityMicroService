package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	server "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/tests/mocks"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRegisterRoutes_RegistersCurrentUserRoute(t *testing.T) {
	identityService := &mocks.MockPublicIdentityService{
		GetUserByIDFunc: func(_ context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
			assert.Equal(t, int32(42), req.Id)
			return &authv1.GetUserResponse{Id: 42}, nil
		},
	}
	tokenManager := &mocks.MockTokenManager{}
	handler := server.NewIdentityHandler(identityService, tokenManager)

	router := gin.New()
	authMiddleware := func(c *gin.Context) {
		c.Set("userID", int32(42))
		c.Next()
	}
	server.RegisterRoutes(router, handler, authMiddleware)

	req := httptest.NewRequest(http.MethodGet, "/api/user/me", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)

	assert.Equal(t, http.StatusOK, response.Code)
}

func TestRegisterRoutes_DoesNotExposeRemovedUsernameLookup(t *testing.T) {
	router := gin.New()
	handler := server.NewIdentityHandler(&mocks.MockPublicIdentityService{}, &mocks.MockTokenManager{})
	server.RegisterRoutes(router, handler, func(c *gin.Context) { c.Next() })

	req := httptest.NewRequest(http.MethodGet, "/api/user/name/john", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)

	assert.Equal(t, http.StatusNotFound, response.Code)
}
