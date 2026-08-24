package middleware

import (
	"context"
	"net/http"
	"strings"

	v1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	service "GoLearning-IdentityMicroService/internal/service"

	"github.com/gin-gonic/gin"
)

type identityMiddlewareBuilder struct {
	iIdentityService *service.InternalIdentityService
}

func NewidentityMiddlewareBuilder(iIdentityService *service.InternalIdentityService) *identityMiddlewareBuilder {
	return &identityMiddlewareBuilder{iIdentityService: iIdentityService}
}

func (b *identityMiddlewareBuilder) Build() gin.HandlerFunc {
	return func(c *gin.Context) {
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
		if err != nil || !resp.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, entities.ErrBadData)
			return
		}

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
