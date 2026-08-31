package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	v1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"GoLearning-IdentityMicroService/internal/logger"
	service "GoLearning-IdentityMicroService/internal/service"

	"github.com/gin-gonic/gin"
)

type identityMiddlewareBuilder struct {
	iIdentityService *service.InternalIdentityService
	logger           *slog.Logger
}

func NewidentityMiddlewareBuilder(iIdentityService *service.InternalIdentityService) *identityMiddlewareBuilder {
	return &identityMiddlewareBuilder{iIdentityService: iIdentityService, logger: logger.New().WithGroup("AuthMiddleware")}
}

func (b *identityMiddlewareBuilder) Build() gin.HandlerFunc {
	return func(c *gin.Context) {
		b.logger.Info("Activating identity middleware")
		tokenStr := bearerFromHeader(c)

		if tokenStr == "" {
			tokenStr, _ = c.Cookie("access_token")
		}

		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, entities.ErrBadData)
			return
		}

		ctx := context.Background()
		resp, err := b.iIdentityService.ValidateToken(ctx, &v1.ValidateTokenRequest{Token: tokenStr})
		if err != nil || resp.UserId == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, entities.ErrBadData)
			return
		}

		b.logger.Info("middleware successful")
		c.Set("userID", int32(resp.UserId))
		c.Next()
	}
}

func bearerFromHeader(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}
