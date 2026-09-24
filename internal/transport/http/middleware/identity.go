package middleware

import (
	"net/http"
	"strings"

	v1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/service"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http/middleware/logger"

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
		log := logger.GetLoggerFromContext(c.Request.Context()).With("component", "AuthMiddleware")
		log.Debug("validating request identity")
		tokenStr := bearerFromHeader(c)

		if tokenStr == "" {
			tokenStr, _ = c.Cookie("access_token")
		}

		if tokenStr == "" {
			log.Warn("request missing access token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, domain.ErrBadRequest)
			return
		}

		resp, err := b.iIdentityService.ValidateToken(c.Request.Context(), &v1.ValidateTokenRequest{Token: tokenStr})
		if err != nil || resp.UserId == 0 {
			log.Warn("request identity validation failed", "err", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, domain.ErrBadRequest)
			return
		}

		log.Debug("request identity validated", "user_id", resp.UserId)
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
