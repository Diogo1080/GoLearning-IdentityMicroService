package service

import (
	"log/slog"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	entities "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/logger"
	store "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/store"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/validation"

	"context"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

type PublicIdentityService struct {
	authv1.UnimplementedPublicIdentityServiceServer
	repo   store.IdentityRepository
	tokens TokenManagerPort
	logger *slog.Logger
}

//TODO make this service depend on User Service

func NewPublicIdentityService(repo store.IdentityRepository, tokens TokenManagerPort) *PublicIdentityService {
	return &PublicIdentityService{repo: repo, tokens: tokens, logger: logger.New().WithGroup("PublicIdentityService")}
}

// Register creates a new user account
func (s *PublicIdentityService) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	s.logger.Info("Register attempt ", "request", req.String())

	// Check if username or email already exists
	_, err := s.repo.GetUserByEmail(req.Email)
	if err == nil {
		s.logger.Error("Error getting user: ", "err", entities.ErrAlreadyExists)
		return &authv1.RegisterResponse{
			Success: false,
		}, entities.ErrAlreadyExists
	}

	// Check if username or email already exists
	_, err = s.repo.GetUserByUsername(req.Username)
	if err == nil {
		s.logger.Error("Error getting user: ", "err", entities.ErrAlreadyExists)
		return &authv1.RegisterResponse{
			Success: false,
		}, entities.ErrAlreadyExists
	}

	// Hash password
	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		s.logger.Error("Error hashing password: ", "err", err)
		return &authv1.RegisterResponse{
			Success: false,
		}, entities.ErrInternalServerError
	}

	birthdate, err := validation.ValidateDate(req.Birthdate)

	if err != nil {
		s.logger.Error("Failed validating date", "err", err)
		return &authv1.RegisterResponse{Success: false}, err
	}

	// Create user
	user := entities.User{
		Username: req.Username,
		Password: hashedPassword,
		Birthday: birthdate,
		Email:    req.Email,
	}

	createdUser, err := s.repo.CreateUser(user)
	if err != nil {
		s.logger.Error("Error creating user: ", "err", err)
		return &authv1.RegisterResponse{
			Success: false,
		}, entities.ErrInternalServerError
	}

	s.logger.Info("Register succesful.", "user", createdUser.ToUserDTO())
	return &authv1.RegisterResponse{
		Success: true,
		UserId:  int32(createdUser.ID),
	}, nil
}

// Login authenticates user and issues JWT tokens
func (s *PublicIdentityService) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	s.logger.Info("Attempting Login", "request", req)

	var user entities.User
	var err error

	if validation.ValidateEmail(req.Usernameoremail) == nil {
		user, err = s.repo.GetUserByEmail(req.Usernameoremail)
	} else if validation.ValidateUsername(req.Usernameoremail) == nil {
		user, err = s.repo.GetUserByUsername(req.Usernameoremail)
	} else {
		s.logger.Error("Invalid Username or Email")
		return nil, entities.ErrBadData
	}

	if err != nil {
		s.logger.Error("User doesn't exist")
		return nil, err
	}

	if !VerifyPassword(req.Password, user.Password) {
		s.logger.Error("Password doesn't match")
		return nil, entities.ErrUnauthorized
	}

	token, err := s.tokens.IssueTokens(ctx, strconv.Itoa(int(user.ID)))
	if err != nil {
		s.logger.Error("Error issuing tokens", "err", err)
		return nil, entities.ErrInternalServerError
	}

	s.logger.Info("Login succesful.")
	return &authv1.LoginResponse{
		AccessToken:  token.Access,
		RefreshToken: token.Refresh,
		UserId:       int32(user.ID),
		Message:      "login successful",
	}, nil
}

// RefreshToken issues new access + refresh tokens using a valid refresh token.
//
// The refreshed tokens belong to the SAME session as the original refresh
// token. Refreshing a token does not create a new login/session.
func (s *PublicIdentityService) RefreshLogin(ctx context.Context, req *authv1.RefreshLoginRequest) (*authv1.LoginResponse, error) {
	s.logger.Info("Attempting to refresh token")

	claims, err := s.tokens.ParseRefresh(req.RefreshToken)
	if err != nil {
		s.logger.Error("Invalid refresh token", "err", err)
		return nil, entities.ErrUnauthorized
	}

	// Make sure the refresh token's user + session are still valid.
	ok, err := s.tokens.ValidateToken(ctx, claims)
	if err != nil {
		s.logger.Error("Error validating refresh token", "err", err)
		return nil, entities.ErrUnauthorized
	}

	if !ok {
		s.logger.Error(
			"Refresh token is revoked or session is no longer valid",
			"user_id", claims.Subject,
			"session_id", claims.SessionID,
		)
		return nil, entities.ErrUnauthorized
	}

	// Issue new tokens for the EXISTING session.
	newTokens, err := s.tokens.IssueTokensForSession(
		ctx,
		claims.Subject,
		claims.SessionID,
	)

	if err != nil {
		s.logger.Error("Error refreshing tokens", "err", err)
		return nil, entities.ErrInternalServerError
	}

	s.logger.Info(
		"Refresh successful",
		"user_id", claims.Subject,
		"session_id", claims.SessionID,
	)

	userid, err := strconv.Atoi(claims.Subject)
	if err != nil {
		return nil, entities.ErrInternalServerError
	}

	return &authv1.LoginResponse{
		AccessToken:  newTokens.Access,
		RefreshToken: newTokens.Refresh,
		UserId:       int32(userid),
		Message:      "login successful",
	}, nil
}

func (s *PublicIdentityService) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	s.logger.Info("Attempting Logout")

	err := s.tokens.RevokeSession(ctx, req.SessionId)

	if err != nil {
		s.logger.Error("Error revoking tokens", "err", err)
		return nil, entities.ErrInternalServerError
	}

	s.logger.Info("Logged out successfully")

	return &authv1.LogoutResponse{
		Message: "logged out successfully",
	}, nil
}

func (s *PublicIdentityService) LogoutAll(ctx context.Context, req *authv1.LogoutAllRequest) (*authv1.LogoutResponse, error) {
	s.logger.Info("Attempting Logout")

	err := s.tokens.RevokeAllTokens(ctx, strconv.Itoa(int(req.UserId)))

	if err != nil {
		s.logger.Error("Error revoking tokens", "err", err)
		return nil, entities.ErrInternalServerError
	}

	s.logger.Info("Logged out successfully")

	return &authv1.LogoutResponse{
		Message: "logged out successfully",
	}, nil
}

func (s *PublicIdentityService) GetUserByID(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	s.logger.Info("Attempting getting user", "request", req)
	user, err := s.repo.GetUserByID(int(req.Id))

	if err != nil {
		s.logger.Error("Failed getting user", "err", err)
		return &authv1.GetUserResponse{}, err
	}

	s.logger.Info("Got user successfully")
	return &authv1.GetUserResponse{
		Id:        int32(user.ID),
		Username:  user.Username,
		Email:     user.Email,
		Birthdate: user.Birthday.String(),
	}, nil
}

func (s *PublicIdentityService) GetUserByEmail(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	s.logger.Info("Attempting getting user", "request", req)
	user, err := s.repo.GetUserByEmail(req.Email)

	if err != nil {
		s.logger.Error("Failed getting user", "err", err)
		return &authv1.GetUserResponse{}, err
	}

	s.logger.Info("Got user successfully")
	return &authv1.GetUserResponse{
		Id:        int32(user.ID),
		Username:  user.Username,
		Email:     user.Email,
		Birthdate: user.Birthday.String(),
	}, nil
}

func (s *PublicIdentityService) GetUserByUsername(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	s.logger.Info("Attempting getting user", "request", req)
	user, err := s.repo.GetUserByUsername(req.Username)

	if err != nil {
		s.logger.Error("Failed getting user", "err", err)
		return &authv1.GetUserResponse{}, err
	}

	s.logger.Info("Got user successfully")
	return &authv1.GetUserResponse{
		Id:        int32(user.ID),
		Username:  user.Username,
		Email:     user.Email,
		Birthdate: user.Birthday.String(),
	}, nil
}

func (s *PublicIdentityService) UpdateUser(ctx context.Context, req *authv1.UpdateUserRequest) (*authv1.UpdateUserResponse, error) {
	s.logger.Info("Attempting update user", "request", req)

	tochange, err := s.repo.GetUserByID(int(req.UserId))
	if err != nil {
		return &authv1.UpdateUserResponse{Success: false}, err
	}

	tochange.Username = req.Username
	tochange.Email = req.Email
	tochange.Birthday, err = validation.ValidateDate(req.Birthdate)

	if err != nil {
		s.logger.Error("Failed validating date", "err", err)
		return &authv1.UpdateUserResponse{Success: false}, err
	}

	err = s.repo.UpdateUser(int(req.UserId), tochange)

	if err != nil {
		s.logger.Error("Failed Updating user", "err", err)
		return &authv1.UpdateUserResponse{Success: false}, err
	}

	s.logger.Info("Update succesful")
	return &authv1.UpdateUserResponse{Success: true}, nil
}

func (s *PublicIdentityService) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {
	s.logger.Info("Attempting update password", "request", req)
	tochange, err := s.repo.GetUserByID(int(req.UserId))

	if err != nil {
		return &authv1.ChangePasswordResponse{Success: false}, err
	}

	if !VerifyPassword(req.CurrentPassword, tochange.Password) {
		s.logger.Error("Password doesn't match")
		return &authv1.ChangePasswordResponse{Success: false}, entities.ErrUnauthorized
	}

	pass, err := HashPassword(req.NewPassword)

	if err != nil {
		s.logger.Error("Failed while hashing password")
		return &authv1.ChangePasswordResponse{Success: false}, entities.ErrInternalServerError
	}

	err = s.repo.UpdatePassword(int(req.UserId), pass)

	if err != nil {
		s.logger.Error("Failed Updating user", "err", err)
		return &authv1.ChangePasswordResponse{Success: false}, err
	}

	s.tokens.RevokeAllTokens(ctx, strconv.Itoa(int(req.UserId)))

	s.logger.Info("Update succesful")
	return &authv1.ChangePasswordResponse{Success: true}, nil
}

func (s *PublicIdentityService) DeleteUser(ctx context.Context, req *authv1.DeleteUserRequest) (*authv1.DeleteUserResponse, error) {
	s.logger.Info("Attempting to delete user", "request", req)
	_, err := s.repo.GetUserByID(int(req.UserId))

	if err != nil {
		return &authv1.DeleteUserResponse{Success: false}, err
	}

	err = s.repo.DeleteUser(int(req.UserId))

	if err != nil {
		return &authv1.DeleteUserResponse{Success: false}, err
	}

	return &authv1.DeleteUserResponse{Success: true}, nil
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
