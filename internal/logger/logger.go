package logger

import (
	"log/slog"
	"os"
	"strings"
)

// New creates a configured slog logger based on APP_ENV
func New() *slog.Logger {
	env := os.Getenv("APP_ENV")
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}

	if strings.ToLower(env) == "production" {
		// JSON format for production (machine-readable, for log aggregation)
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		// Text format for development (human-readable)
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
