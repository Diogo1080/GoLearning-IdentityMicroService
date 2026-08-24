package domain

import "errors"

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")

	ErrBadData = errors.New("bad data")

	ErrUnauthorized = errors.New("unauthorized")

	ErrDatabaseFailed      = errors.New("Database failed")
	ErrServiceUnavailable  = errors.New("Service unavailable")
	ErrInternalServerError = errors.New("Internal server error")
	ErrConflict            = errors.New("Conflict")
)
