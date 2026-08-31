package service

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"GoLearning-IdentityMicroService/internal/logger"
	store "GoLearning-IdentityMicroService/internal/store"
	tokens "GoLearning-IdentityMicroService/internal/tokens"
	"GoLearning-IdentityMicroService/internal/validation"
	"log/slog"

	"fmt"

	"context"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

type PublicIdentityService struct {
	authv1.UnimplementedPublicIdentityServiceServer
	repo   store.IdentityRepository
	rds    *store.Redis
	logger *slog.Logger
}

//TODO make this service depend on User Service

func NewPublicIdentityService(repo store.IdentityRepository, rds *store.Redis) *PublicIdentityService {
	return &PublicIdentityService{repo: repo, rds: rds, logger: logger.New().WithGroup("PublicIdentityService")}
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

	birthdate, _ := validation.ValidateDate(req.Birthdate)

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

	token, err := tokens.IssueTokens(strconv.Itoa(int(user.ID)))
	if err != nil {
		s.logger.Error("Error issuing tokens", "err", err)
		return nil, entities.ErrInternalServerError
	}

	if err := tokens.Persist(ctx, s.rds, token); err != nil {
		s.logger.Error("Error persisting tokens", "err", err)
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

// Logout revokes access token
func (s *PublicIdentityService) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	s.logger.Info("Attempting Logout", "request", req)

	claims, err := tokens.ParseAccess(req.Token)
	if err != nil {
		s.logger.Error("Invalid token")
		return nil, entities.ErrBadData
	}

	err = s.rds.DelJTI(ctx, "access:"+claims.ID)
	if err != nil {
		s.logger.Error("Failed to delete token")
		return nil, entities.ErrInternalServerError
	}

	s.logger.Info("logged out successfully")
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
	tochange.Birthday, _ = validation.ValidateDate(req.Birthdate)
	tochange.Email = req.Email

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
	fmt.Print(len(bytes))
	return string(bytes), err
}

// VerifyPassword verifies if the given password matches the stored hash.
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
