package http

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
)

func mapDomainError(err error) (int, domain.Response) {
	switch {
	case errors.Is(err, domain.ErrBadRequest):
		return http.StatusBadRequest, domain.ErrBadRequest
	case errors.Is(err, domain.ErrUnauthorized):
		return http.StatusUnauthorized, domain.ErrUnauthorized
	case errors.Is(err, domain.ErrNotFound):
		return http.StatusNotFound, domain.ErrNotFound
	case errors.Is(err, domain.ErrConflict):
		return http.StatusConflict, domain.ErrConflict
	case errors.Is(err, domain.ErrForbidden):
		return http.StatusForbidden, domain.ErrForbidden
	default:
		// Log the actual error internally
		slog.Error("Unhandled domain error", "error", err)
		return http.StatusInternalServerError, domain.ErrInternal
	}
}
