package tests

import (
	"GoLearning-IdentityMicroService/internal/service"
	"GoLearning-IdentityMicroService/tests/mocks"

	"GoLearning-IdentityMicroService/internal/domain"

	"testing"

	"golang.org/x/crypto/bcrypt"
)

const (
	testUserIdString = "42"
	testUserId       = 42
	testUsername     = "john_doe"
	testEmail        = "john@example.com"
	testPassword     = "password123"
	testJWTSecret    = "test-secret"
)

func newPublicIdentityService(t *testing.T) (identityRepo *mocks.MockIdentityRepository, TokenManager *mocks.MockTokenManager, publicIdentityService *service.PublicIdentityService) {
	t.Helper()

	repo := &mocks.MockIdentityRepository{}
	TokenManager = &mocks.MockTokenManager{}

	svc := service.NewPublicIdentityService(repo, TokenManager)

	return repo, TokenManager, svc
}

func testUser() domain.User {
	hashedPassword, err := service.HashPassword(testPassword)
	if err != nil {
		panic(err)
	}

	return domain.User{
		ID:       int64(testUserId),
		Username: testUsername,
		Email:    testEmail,
		Password: hashedPassword,
	}
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// VerifyPassword verifies if the given password matches the stored hash.
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
