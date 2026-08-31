package service

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"GoLearning-IdentityMicroService/internal/logger"
	store "GoLearning-IdentityMicroService/internal/store"
	tokens "GoLearning-IdentityMicroService/internal/tokens"
	"context"
	"log/slog"
	"strconv"
)

type InternalIdentityService struct {
	authv1.UnimplementedInternalIdentityServiceServer
	repo   store.IdentityRepository
	rds    *store.Redis
	logger *slog.Logger
}

func NewInternalIdentityService(repo store.IdentityRepository, rds *store.Redis) *InternalIdentityService {
	return &InternalIdentityService{repo: repo, rds: rds, logger: logger.New().WithGroup("InternalIdentityService")}
}

// ValidateToken checks if access token is valid and not revoked
func (s *InternalIdentityService) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	s.logger.Info("Attempting to validate token")
	claims, err := tokens.ParseAccess(req.Token)
	if err != nil {
		s.logger.Error("Invalid Token")
		return nil, entities.ErrBadData
	}

	_, err = s.rds.GetUserByJTI(ctx, "access:"+claims.ID)
	if err != nil {
		s.logger.Error("User is not Logged in")
		return nil, entities.ErrNotFound
	}

	userID, err := strconv.Atoi(claims.Subject)

	if err != nil {
		s.logger.Error("Invalid User ID")
		return nil, entities.ErrInternalServerError
	}

	s.logger.Info("Validate succesful.")
	return &authv1.ValidateTokenResponse{
		UserId: int32(userID),
	}, nil
}

// RefreshToken issues new tokens using refresh token
func (s *InternalIdentityService) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.RefreshTokenResponse, error) {
	s.logger.Info("Attempting to Refresh Token", "request", req)

	claims, err := tokens.ParseRefresh(req.RefreshToken)
	if err != nil {
		s.logger.Error("Invalid token")
		return nil, entities.ErrBadData
	}

	_, err = s.rds.GetUserByJTI(ctx, "refresh:"+claims.ID)
	if err != nil {
		s.logger.Error("User is not logged in")
		return nil, entities.ErrNotFound
	}

	newTokens, err := tokens.IssueTokens(claims.Subject)
	if err != nil {
		s.logger.Error("Error refreshing tokens", "err", err)
		return nil, entities.ErrInternalServerError
	}

	if err := tokens.Persist(ctx, s.rds, newTokens); err != nil {
		s.logger.Error("Error persisting refreshed tokens", "err", err)
		return nil, entities.ErrInternalServerError
	}

	s.logger.Info("Refresh succesful")
	return &authv1.RefreshTokenResponse{
		AccessToken:  newTokens.Access,
		RefreshToken: newTokens.Refresh,
	}, nil
}
