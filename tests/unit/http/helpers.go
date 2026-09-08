package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/logger"
	server "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/tests/mocks"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
	_ = logger.New()
}

// ============================================================
// TEST ROUTER / HELPERS
// ============================================================

func setupRouter(t *testing.T, mockSvc *mocks.MockPublicIdentityService, tokenManager *mocks.MockTokenManager) *gin.Engine {
	t.Helper()

	handler := server.NewIdentityHandler(mockSvc, tokenManager)

	router := gin.New()

	router.Use(func(c *gin.Context) {
		token := c.GetHeader("Authorization")

		if token == "" {
			if cookie, err := c.Cookie("access_token"); err == nil {
				token = cookie
			}
		}

		switch token {
		case "Bearer user42_token":
			c.Set("userID", int32(42))

		case "Bearer user99_token":
			c.Set("userID", int32(99))

		case "Bearer valid_jwt_token":
			c.Set("userID", int32(42))

		case "Bearer user42_sessionA_token":
			c.Set("userID", int32(42))
			c.Set("sessionID", "session-A")

		case "Bearer user42_sessionB_token":
			c.Set("userID", int32(42))
			c.Set("sessionID", "session-B")

		case "Bearer user42_sessionC_token":
			c.Set("userID", int32(42))
			c.Set("sessionID", "session-C")

		case "Bearer user99_sessionA_token":
			c.Set("userID", int32(99))
			c.Set("sessionID", "user99-session-A")
		}

		c.Next()
	})

	router.POST("/register", handler.HandleRegister)
	router.POST("/login", handler.HandleLogin)
	router.POST("/logout", handler.HandleLogout)
	router.POST("/logout/all", handler.HandleLogoutAll)

	router.GET("/users/email/:email", handler.HandleGetUserByEmail)
	router.GET("/users/username/:username", handler.HandleGetUserByUsername)
	router.GET("/users/:id", handler.HandleGetUserByID)

	router.PUT("/users", handler.HandleUpdateUser)
	router.PATCH("/password", handler.HandleUpdatePassword)
	router.DELETE("/users/:id", handler.HandleDeleteUser)

	return router
}

// ============================================================
// REQUEST HELPERS
// ============================================================

func jsonRequest(t *testing.T, method string, path string, body interface{}) *http.Request {
	t.Helper()
	var reader *bytes.Reader

	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		data, err := json.Marshal(body)
		if err != nil {
			panic(err)
		}

		reader = bytes.NewReader(data)
	}

	req := httptest.NewRequest(
		method,
		path,
		reader,
	)

	req.Header.Set(
		"Content-Type",
		"application/json",
	)

	return req
}

// authenticatedRequest creates a request with a Bearer token.
//
// Example:
//
//	req := authenticatedRequest(
//		http.MethodPost,
//		"/logout",
//		nil,
//		"user42_sessionA_token",
//	)
func authenticatedRequest(t *testing.T, method string, path string, body interface{}, token string) *http.Request {
	t.Helper()

	req := jsonRequest(
		t,
		method,
		path,
		body,
	)

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)

	return req
}

// authenticatedSessionRequest is an explicit helper for session-aware
// tests.
//
// The router maps the test token to a user + session:
//
//	user42_sessionA_token -> user 42 / session-A
//	user42_sessionB_token -> user 42 / session-B
//	user42_sessionC_token -> user 42 / session-C
func authenticatedSessionRequest(t *testing.T, method string, path string, body interface{}, userID int32, sessionID string) *http.Request {
	t.Helper()

	req := jsonRequest(
		t,
		method,
		path,
		body,
	)

	// Keep the mapping in one place so tests don't have to know
	// how the mock authentication middleware works.
	token := sessionTestToken(t, userID, sessionID)

	req.Header.Set(
		"Authorization",
		"Bearer "+token,
	)

	return req
}

// sessionTestToken returns the mock token understood by setupRouter.
//
// This is intentionally a test-only mapping. Production code should
// never construct tokens this way.
func sessionTestToken(
	t *testing.T,
	userID int32,
	sessionID string,
) string {
	t.Helper()
	switch {
	case userID == 42 && sessionID == "session-A":
		return "user42_sessionA_token"

	case userID == 42 && sessionID == "session-B":
		return "user42_sessionB_token"

	case userID == 42 && sessionID == "session-C":
		return "user42_sessionC_token"

	case userID == 99 && sessionID == "user99-session-A":
		return "user99_sessionA_token"

	default:
		return "invalid_session_token"
	}
}
