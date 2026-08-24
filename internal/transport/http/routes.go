package http

import (
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine, identityHandler *IdentityHandler, identiyMiddleware gin.HandlerFunc) *gin.Engine {
	// Public routes (no auth required)
	public := r.Group("/api")
	public.POST("/register", identityHandler.HandleRegister)
	public.POST("/login", identityHandler.HandleLogin)
	public.POST("/logout", identityHandler.HandleLogout)

	// Protected routes (require valid JWT token via auth microservice)
	protected := r.Group("/api")
	protected.Use(identiyMiddleware)

	// User endpoints (profile management only)
	protected.GET("/user/id/:id", identityHandler.HandleGetUserByID)
	protected.GET("/user/name/:username", identityHandler.HandleGetUserByUsername)
	protected.PATCH("/user/password/:id", identityHandler.HandleChangePassword)
	protected.PUT("/user/profile", identityHandler.HandleUpdateProfile)

	return r
}
