package domain

import (
	"fmt"
)

type Response struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e Response) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

var (
	ErrBadRequest         = Response{Code: "bad_request", Message: "invalid or malformed request data"}
	ErrUnauthorized       = Response{Code: "unauthorized", Message: "authentication required"}
	ErrForbidden          = Response{Code: "forbidden", Message: "access denied"}
	ErrNotFound           = Response{Code: "not_found", Message: "requested resource not found"}
	ErrConflict           = Response{Code: "conflict", Message: "resource already exists"}
	ErrInternal           = Response{Code: "internal_error", Message: "an unexpected error occurred"}
	ErrServiceUnavailable = Response{Code: "service_unavailable", Message: "service temporarily unavailable"}

	SuccessResponse = Response{Code: "success", Message: "Success"}
)
