package service

import (
	"context"
	"log/slog"
	"strconv"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	entities "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/logger"
	store "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/store"
)

type InternalIdentityService struct {
	authv1.UnimplementedInternalIdentityServiceServer
	repo   store.IdentityRepository
	tokens TokenManagerPort
	logger *slog.Logger
}

func NewInternalIdentityService(repo store.IdentityRepository, tokens TokenManagerPort) *InternalIdentityService {
	return &InternalIdentityService{repo: repo, tokens: tokens, logger: logger.New().WithGroup("InternalIdentityService")}
}

// ValidateToken checks if an access token is valid and not revoked.
//
// A token is considered valid when:
//   - the JWT signature is valid
//   - the token is an access token
//   - the user exists
//   - the user version matches Redis
//   - the session exists
//   - the session version matches Redis
func (s *InternalIdentityService) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	s.logger.Info("Attempting to validate token")

	claims, err := s.tokens.ParseAccess(req.Token)
	if err != nil {
		s.logger.Error("Invalid token", "err", err)
		return nil, entities.ErrUnauthorized
	}

	ok, err := s.tokens.ValidateToken(ctx, claims)
	if err != nil {
		s.logger.Error("Error validating token", "err", err)
		return nil, entities.ErrInternalServerError
	}

	if !ok {
		s.logger.Error(
			"Token is revoked or session is no longer valid",
			"user_id", claims.Subject,
			"session_id", claims.SessionID,
		)
		return nil, entities.ErrUnauthorized
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 32)
	if err != nil {
		s.logger.Error("Invalid user ID", "err", err)
		return nil, entities.ErrInternalServerError
	}

	s.logger.Info(
		"Token validation successful",
		"user_id", claims.Subject,
		"session_id", claims.SessionID,
	)

	return &authv1.ValidateTokenResponse{
		UserId: int32(userID),
	}, nil
}
