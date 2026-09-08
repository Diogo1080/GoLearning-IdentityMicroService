package mocks

import (
	"GoLearning-IdentityMicroService/internal/tokens"
	"context"

	"github.com/gin-gonic/gin"
)

// MockTokenManager implements tokens.TokenManager interface for testing
type MockTokenManager struct {
	IssueTokensFunc           func(ctx context.Context, userID string) (*tokens.Tokens, error)
	IssueTokensForSessionFunc func(ctx context.Context, userID string, sessionID string) (*tokens.Tokens, error)

	ClearAuthCookiesFunc func(ctx *gin.Context)

	GetUserIDFromAccessTokenFunc     func(token string) (string, error)
	GetUserIDFromRefreshTokenFunc    func(token string) (string, error)
	GetSessionIDFromAccessTokenFunc  func(token string) (string, error)
	GetSessionIDFromRefreshTokenFunc func(token string) (string, error)

	ParseAccessFunc   func(token string) (*tokens.Claims, error)
	ParseRefreshFunc  func(token string) (*tokens.Claims, error)
	ValidateTokenFunc func(ctx context.Context, claims *tokens.Claims) (bool, error)

	RevokeSessionFunc   func(ctx context.Context, sessionID string) error
	RevokeAllTokensFunc func(ctx context.Context, userID string) error
}

func (m *MockTokenManager) RevokeAllTokens(ctx context.Context, userID string) error {
	if m.RevokeAllTokensFunc != nil {
		return m.RevokeAllTokensFunc(ctx, userID)
	}
	return nil
}

func (m *MockTokenManager) RevokeSession(ctx context.Context, sessionID string) error {
	if m.RevokeSessionFunc != nil {
		return m.RevokeSessionFunc(ctx, sessionID)
	}
	return nil
}

func (m *MockTokenManager) IssueTokens(ctx context.Context, userID string) (*tokens.Tokens, error) {
	if m.IssueTokensFunc != nil {
		return m.IssueTokensFunc(ctx, userID)
	}
	return nil, nil
}

func (m *MockTokenManager) ClearAuthCookies(ctx *gin.Context) {
	if m.ClearAuthCookiesFunc != nil {
		m.ClearAuthCookiesFunc(ctx)
	}
}

func (m *MockTokenManager) GetSessionIDFromAccessToken(token string) (string, error) {
	if m.GetSessionIDFromAccessTokenFunc != nil {
		return m.GetSessionIDFromAccessTokenFunc(token)
	}

	return "", nil
}

func (m *MockTokenManager) GetUserIDFromAccessToken(token string) (string, error) {
	if m.GetUserIDFromAccessTokenFunc != nil {
		return m.GetUserIDFromAccessTokenFunc(token)
	}
	return "", nil
}

func (m *MockTokenManager) GetUserIDFromRefreshToken(token string) (string, error) {
	if m.GetUserIDFromRefreshTokenFunc != nil {
		return m.GetUserIDFromRefreshTokenFunc(token)
	}
	return "", nil
}

func (m *MockTokenManager) GetSessionIDFromRefreshToken(token string) (string, error) {
	if m.GetSessionIDFromRefreshTokenFunc != nil {
		return m.GetSessionIDFromRefreshTokenFunc(token)
	}
	return "", nil
}

func (m *MockTokenManager) ParseAccess(token string) (*tokens.Claims, error) {
	if m.ParseAccessFunc != nil {
		return m.ParseAccessFunc(token)
	}

	return nil, nil
}

func (m *MockTokenManager) ParseRefresh(token string) (*tokens.Claims, error) {
	if m.ParseRefreshFunc != nil {
		return m.ParseRefreshFunc(token)
	}

	return nil, nil
}

func (m *MockTokenManager) ValidateToken(ctx context.Context, claims *tokens.Claims) (bool, error) {
	if m.ValidateTokenFunc != nil {
		return m.ValidateTokenFunc(ctx, claims)
	}

	return false, nil
}

func (m *MockTokenManager) IssueTokensForSession(ctx context.Context, userID string, sessionID string) (*tokens.Tokens, error) {
	if m.IssueTokensForSessionFunc != nil {
		return m.IssueTokensForSessionFunc(ctx, userID, sessionID)
	}

	return nil, nil
}
