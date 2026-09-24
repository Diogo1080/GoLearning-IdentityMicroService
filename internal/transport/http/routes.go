package http

import (
	"log/slog"
	"net/http"

	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http/middleware/logger"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine, identityHandler *IdentityHandler, identiyMiddleware gin.HandlerFunc) *gin.Engine {
	r.Use(logger.RequestContextLogger(slog.Default()))

	// Public routes (no auth required)
	public := r.Group("/api")
	public.POST("/register", identityHandler.HandleRegister)

	public.POST("/login", identityHandler.HandleLogin)
	public.POST("/refresh", identityHandler.HandleRefreshLogin)

	public.POST("/logout", identityHandler.HandleLogout)
	public.POST("/logout/all", identityHandler.HandleLogoutAll)

	public.GET("/health", Health)
	// Protected routes (require valid JWT token via auth microservice)
	protected := r.Group("/api")
	protected.Use(identiyMiddleware)

	// User endpoints (profile management only)
	protected.GET("/users/me", identityHandler.HandleGetCurrentUser)
	protected.GET("/user/email/:email", identityHandler.HandleGetUserByEmail)
	protected.PATCH("/user/password/:id", identityHandler.HandleUpdatePassword)
	protected.PUT("/user", identityHandler.HandleUpdateUser)
	protected.DELETE("/user/id/:id", identityHandler.HandleDeleteUser)

	return r
}

func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
}
