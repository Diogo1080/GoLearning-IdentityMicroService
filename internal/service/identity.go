package service

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	store "GoLearning-IdentityMicroService/internal/store"
	tokens "GoLearning-IdentityMicroService/internal/tokens"

	"fmt"
	"regexp"
	"strings"

	"context"
	"log"
	"strconv"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type PublicIdentityService struct {
	authv1.UnimplementedPublicIdentityServiceServer
	repo store.IdentityRepository
	rds  *store.Redis
}

type InternalIdentityService struct {
	authv1.UnimplementedInternalIdentityServiceServer
	repo store.IdentityRepository
	rds  *store.Redis
}

func NewPublicIdentityService(repo store.IdentityRepository, rds *store.Redis) *PublicIdentityService {
	return &PublicIdentityService{repo: repo, rds: rds}
}

func NewInternalIdentityService(repo store.IdentityRepository, rds *store.Redis) *InternalIdentityService {
	return &InternalIdentityService{repo: repo, rds: rds}
}

// Register creates a new user account
func (s *PublicIdentityService) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	// Check if username or email already exists
	_, err := s.repo.GetUserByEmail(req.Email)
	if err == nil {
		return &authv1.RegisterResponse{
			Success: false,
			Error:   entities.ErrBadData.Error(),
		}, nil
	}

	if err := ValidateRegisterRequest(req.Username, req.Email, req.Password); err != nil {
		return &authv1.RegisterResponse{
			Success: false,
			Error:   entities.ErrBadData.Error(),
		}, nil
	}

	// Hash password
	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return &authv1.RegisterResponse{
			Success: false,
			Error:   entities.ErrInternalServerError.Error(),
		}, nil
	}

	// Create user
	user := entities.User{
		Username: req.Username,
		Password: hashedPassword,
	}

	createdUser, err := s.repo.CreateUser(user)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		return &authv1.RegisterResponse{
			Success: false,
			Error:   entities.ErrInternalServerError.Error(),
		}, nil
	}

	return &authv1.RegisterResponse{
		Success: true,
		UserId:  int32(createdUser.ID),
	}, nil
}

// Login authenticates user and issues JWT tokens
func (s *PublicIdentityService) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	var user entities.User
	var err error

	if ValidateEmail(req.Usernameoremail) == nil {
		user, err = s.repo.GetUserByEmail(req.Usernameoremail)
	} else {
		user, err = s.repo.GetUserByUsername(req.Usernameoremail)
	}

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, entities.ErrBadData.Error())
	}

	if !VerifyPassword(req.Password, user.Password) {
		return nil, status.Error(codes.Unauthenticated, entities.ErrBadData.Error())
	}

	token, err := tokens.IssueTokens(strconv.Itoa(int(user.ID)))
	if err != nil {
		log.Printf("Error issuing tokens: %v", err)
		return nil, status.Error(codes.Internal, entities.ErrInternalServerError.Error())
	}

	if err := tokens.Persist(ctx, s.rds, token); err != nil {
		log.Printf("Error persisting tokens: %v", err)
		return nil, status.Error(codes.Internal, entities.ErrInternalServerError.Error())
	}

	return &authv1.LoginResponse{
		AccessToken:  token.Access,
		RefreshToken: token.Refresh,
		UserId:       int32(user.ID),
		Message:      "login successful",
	}, nil
}

// Logout revokes access token
func (s *PublicIdentityService) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	claims, err := tokens.ParseAccess(req.Token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, entities.ErrBadData.Error())
	}

	s.rds.DelJTI(ctx, "access:"+claims.ID)

	return &authv1.LogoutResponse{
		Message: "logged out successfully",
	}, nil
}

// ValidateToken checks if access token is valid and not revoked
func (s *InternalIdentityService) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	claims, err := tokens.ParseAccess(req.Token)
	if err != nil {
		return &authv1.ValidateTokenResponse{
			Valid: false,
			Error: err.Error(),
		}, nil
	}

	_, err = s.rds.GetUserByJTI(ctx, "access:"+claims.ID)
	if err != nil {
		return &authv1.ValidateTokenResponse{
			Valid: false,
			Error: "token revoked",
		}, nil
	}

	userID, _ := strconv.Atoi(claims.Subject)
	return &authv1.ValidateTokenResponse{
		Valid:  true,
		UserId: int32(userID),
	}, nil
}

// RefreshToken issues new tokens using refresh token
func (s *InternalIdentityService) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.RefreshTokenResponse, error) {
	claims, err := tokens.ParseRefresh(req.RefreshToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, entities.ErrBadData.Error())
	}

	_, err = s.rds.GetUserByJTI(ctx, "refresh:"+claims.ID)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, entities.ErrBadData.Error())
	}

	newTokens, err := tokens.IssueTokens(claims.Subject)
	if err != nil {
		log.Printf("Error refreshing tokens: %v", err)
		return nil, status.Error(codes.Internal, entities.ErrInternalServerError.Error())
	}

	if err := tokens.Persist(ctx, s.rds, newTokens); err != nil {
		log.Printf("Error persisting refreshed tokens: %v", err)
		return nil, status.Error(codes.Internal, entities.ErrInternalServerError.Error())
	}

	return &authv1.RefreshTokenResponse{
		AccessToken:  newTokens.Access,
		RefreshToken: newTokens.Refresh,
	}, nil
}



func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	fmt.Print(len(bytes))
	return string(bytes), err
}

// VerifyPassword verifies if the given password matches the stored hash.
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func ValidateEmail(email string) error {
	email = strings.TrimSpace(email)

	if email == "" || len(email) > 254 {
		return entities.ErrBadData
	}

	if !emailRegex.MatchString(email) {
		return entities.ErrBadData
	}

	return nil
}

func ValidateRegisterRequest(username, email, password string) error {
	if len(username) < 3 || len(username) > 50 {
		return entities.ErrBadData
	}

	if err := ValidateEmail(email); err != nil {
		return entities.ErrBadData
	}

	if len(password) < 6 {
		return entities.ErrBadData
	}

	return nil
}
