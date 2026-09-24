package logger

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// contextKeyType prevents key collisions in context values
type contextKeyType string

const (
	LoggerContextKey contextKeyType = "request_logger"
	RequestIDKey     contextKeyType = "request_id"
)

// RequestID generates a unique identifier for traceability
func generateRequestID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().UnixNano()%1000000)
}

// RequestContextLogger creates middleware that injects a request-scoped logger
// into both gin.Context and context.Context for full propagation through handlers and services
func RequestContextLogger(baseLogger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract or generate request ID
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}

		// Store in gin.Context for direct access in handlers
		c.Set(string(RequestIDKey), requestID)

		// Create request-scoped logger with common attributes
		reqLogger := baseLogger.With(
			"request_id", requestID,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"client_ip", c.ClientIP(),
		)

		// Wrap context.Context to propagate logger downstream
		wrappedCtx := context.WithValue(c.Request.Context(), LoggerContextKey, reqLogger)
		wrappedCtx = context.WithValue(wrappedCtx, RequestIDKey, requestID)

		// Replace request context in gin.Context so handlers and services receive it
		c.Request = c.Request.WithContext(wrappedCtx)

		// Start timing
		start := time.Now()

		// Continue processing
		c.Next()

		// Post-processing logging with response metrics
		duration := time.Since(start)
		logWithAttrs := reqLogger.With(
			"status", c.Writer.Status(),
			"duration_ms", duration.Milliseconds(),
			"bytes_written", c.Writer.Size(),
		)

		// Log severity based on HTTP status
		switch {
		case c.Writer.Status() >= http.StatusInternalServerError:
			logWithAttrs.Error("request failed", "err", "server_error")
		case c.Writer.Status() >= http.StatusBadRequest:
			logWithAttrs.Warn("request completed with client error")
		default:
			logWithAttrs.Debug("request completed successfully")
		}
	}
}

// GetLoggerFromContext retrieves the request-scoped logger from context.Context
// Falls back to default logger if none found
func GetLoggerFromContext(ctx context.Context) *slog.Logger {
	if val := ctx.Value(LoggerContextKey); val != nil {
		if logger, ok := val.(*slog.Logger); ok {
			return logger
		}
	}
	return slog.Default()
}

// GetRequestIDFromContext retrieves request ID from context.Context
func GetRequestIDFromContext(ctx context.Context) string {
	if val := ctx.Value(RequestIDKey); val != nil {
		if requestID, ok := val.(string); ok {
			return requestID
		}
	}
	return ""
}

// WithRequestLogger wraps an existing context with additional logger attributes
// Useful for creating child contexts with more specific log metadata
func WithRequestLogger(ctx context.Context, attrs ...slog.Attr) context.Context {
	baseLogger := GetLoggerFromContext(ctx)
	childLogger := baseLogger.With(attrs)
	return context.WithValue(ctx, LoggerContextKey, childLogger)
}

// AddAttributesToLogger adds attributes to the logger stored in context
// Returns a modified context with the augmented logger
func AddAttributesToLogger(ctx context.Context, attrs ...slog.Attr) context.Context {
	return WithRequestLogger(ctx, attrs...)
}
