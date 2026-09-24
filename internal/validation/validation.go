package validation

import (
	"regexp"
	"strings"
	"time"

	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
)

func ValidateId(id string) bool {
	if len(id) == 0 || !regexp.MustCompile(`^[0-9]+$`).MatchString(id) {
		return true
	}

	return false
}

func ValidateRegisterRequest(username, email, password, birthate string) error {
	if err := ValidateUsername(username); err != nil {
		return domain.ErrBadRequest
	}

	if err := ValidateEmail(email); err != nil {
		return domain.ErrBadRequest
	}

	if err := ValidatePassword(password); err != nil {
		return domain.ErrBadRequest
	}

	if _, err := ValidateDate(birthate); err != nil {
		return domain.ErrBadRequest
	}

	return nil
}

func ValidateUsername(username string) error {
	if len(username) < 3 || len(username) > 50 {
		return domain.ErrBadRequest
	}
	return nil
}

func ValidatePassword(password string) error {
	if len(password) < 6 {
		return domain.ErrBadRequest
	}
	return nil
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func ValidateEmail(email string) error {
	email = strings.TrimSpace(email)

	if email == "" || len(email) > 254 {
		return domain.ErrBadRequest
	}

	if !emailRegex.MatchString(email) {
		return domain.ErrBadRequest
	}

	return nil
}

func ValidateDate(dateStr string) (time.Time, error) {

	date, err := time.Parse("2006-01-02", dateStr)

	if err != nil {
		return time.Now(), domain.ErrBadRequest
	}

	return date, nil
}
