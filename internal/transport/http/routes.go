package http

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http/middleware/logger"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

//TODO: OpenAPI generate schema

func RegisterRoutes(r *gin.Engine, identityHandler *IdentityHandler, identiyMiddleware gin.HandlerFunc, readiness ...gin.HandlerFunc) *gin.Engine {
	r.Use(logger.RequestContextLogger(slog.Default()))
	readyHandler := func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	}
	if len(readiness) > 0 && readiness[0] != nil {
		readyHandler = readiness[0]
	}

	// Public routes (no auth required)
	public := r.Group("/api")
	public.POST("/register", identityHandler.HandleRegister)

	public.POST("/login", identityHandler.HandleLogin)
	public.POST("/refresh", identityHandler.HandleRefreshLogin)

	public.POST("/logout", identityHandler.HandleLogout)
	public.POST("/logout/all", identityHandler.HandleLogoutAll)

	public.GET("/health", Health)
	public.GET("/livez", Health)
	public.GET("/readyz", readyHandler)
	public.GET("/ready", readyHandler)
	// Protected routes (require valid JWT token via auth microservice)
	protected := r.Group("/api")
	protected.Use(identiyMiddleware)

	// User endpoints (profile management only)
	protected.GET("/user/me", identityHandler.HandleGetCurrentUser)
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

func Readiness(db *sql.DB, redisClient *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()

		if err := db.PingContext(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "dependency": "postgres"})
			return
		}

		if err := redisClient.Ping(ctx).Err(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "dependency": "redis"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	}
}
