package service

import (
	"context"

	tokens "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/tokens"
)

type TokenManagerPort interface {
	IssueTokens(ctx context.Context, userID string) (*tokens.Tokens, error)

	GetUserIDFromAccessToken(token string) (string, error)
	GetSessionIDFromAccessToken(token string) (string, error)

	ParseAccess(token string) (*tokens.Claims, error)
	ParseRefresh(token string) (*tokens.Claims, error)

	ValidateToken(ctx context.Context, claims *tokens.Claims) (bool, error)

	IssueTokensForSession(ctx context.Context, userID string, sessionID string) (*tokens.Tokens, error)

	RevokeSession(ctx context.Context, sessionID string) error
	RevokeAllTokens(ctx context.Context, userID string) error
}
