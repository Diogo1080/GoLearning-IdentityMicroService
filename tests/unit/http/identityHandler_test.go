// tests/unit/transport/http/identity_handler_test.go
package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"GoLearning-IdentityMicroService/internal/logger"
	server "GoLearning-IdentityMicroService/internal/transport/http"
	"GoLearning-IdentityMicroService/tests/mocks"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
	_ = logger.New()
}

// ============================================================
// TEST ROUTER / HELPERS
// ============================================================

func setupRouter(mockSvc *mocks.MockPublicIdentityService) *gin.Engine {
	handler := server.NewIdentityHandler(mockSvc)

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
		}

		c.Next()
	})

	router.POST("/register", handler.HandleRegister)
	router.POST("/login", handler.HandleLogin)

	router.GET("/users/email/:email", handler.HandleGetUserByEmail)
	router.GET("/users/username/:username", handler.HandleGetUserByUsername)
	router.GET("/users/:id", handler.HandleGetUserByID)

	router.PUT("/users", handler.HandleUpdateUser)
	router.PATCH("/password", handler.HandleUpdatePassword)

	router.DELETE("/users/:id", handler.HandleDeleteUser)

	router.POST("/logout", handler.HandleLogout)

	return router
}

func jsonRequest(
	method string,
	path string,
	body interface{},
) *http.Request {
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

	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")

	return req
}

func authenticatedRequest(
	method string,
	path string,
	body interface{},
	token string,
) *http.Request {
	req := jsonRequest(method, path, body)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}
