package service

import (
	"context"
	"log/slog"
	"strconv"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/store"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http/middleware/logger"
)

type InternalIdentityService struct {
	authv1.UnimplementedInternalIdentityServiceServer
	repo   store.IdentityRepository
	tokens TokenManagerPort
}

func NewInternalIdentityService(repo store.IdentityRepository, tokens TokenManagerPort) *InternalIdentityService {
	return &InternalIdentityService{repo: repo, tokens: tokens}
}

func internalServiceLogger(ctx context.Context) *slog.Logger {
	return logger.GetLoggerFromContext(ctx).With("service", "InternalIdentityService")
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
	log := internalServiceLogger(ctx).With("operation", "validate_token")
	log.Info("attempting to validate token")

	claims, err := s.tokens.ParseAccess(req.Token)
	if err != nil {
		log.Error("invalid token", "err", err)
		return nil, domain.ErrUnauthorized
	}

	ok, err := s.tokens.ValidateToken(ctx, claims)
	if err != nil {
		log.Error("error validating token", "err", err)
		return nil, domain.ErrInternal
	}

	if !ok {
		log.Error(
			"Token is revoked or session is no longer valid",
			"user_id", claims.Subject,
			"session_id", claims.SessionID,
		)
		return nil, domain.ErrUnauthorized
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 32)
	if err != nil {
		log.Error("invalid user ID", "err", err)
		return nil, domain.ErrInternal
	}

	log.Info(
		"Token validation successful",
		"user_id", claims.Subject,
		"session_id", claims.SessionID,
	)

	return &authv1.ValidateTokenResponse{
		UserId: int32(userID),
	}, nil
}
