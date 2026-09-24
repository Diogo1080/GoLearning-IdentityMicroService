package service

import (
	"context"
	"log/slog"
	"strconv"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/store"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http/middleware/logger"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/validation"

	"golang.org/x/crypto/bcrypt"
)

type PublicIdentityService struct {
	authv1.UnimplementedPublicIdentityServiceServer
	repo   store.IdentityRepository
	tokens TokenManagerPort
}

//TODO make this service depend on User Service

func NewPublicIdentityService(repo store.IdentityRepository, tokens TokenManagerPort) *PublicIdentityService {
	return &PublicIdentityService{repo: repo, tokens: tokens}
}

func publicServiceLogger(ctx context.Context) *slog.Logger {
	return logger.GetLoggerFromContext(ctx).With("service", "PublicIdentityService")
}

// Register creates a new user account
func (s *PublicIdentityService) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	log := publicServiceLogger(ctx).With("operation", "register")

	log.Info("register attempt", "username", req.Username)

	// Check if username or email already exists
	_, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err == nil {
		log.Warn("registration rejected: email already exists")
		return &authv1.RegisterResponse{
			Success: false,
		}, domain.ErrConflict
	}

	// Check if username or email already exists
	_, err = s.repo.GetUserByUsername(ctx, req.Username)
	if err == nil {
		log.Warn("registration rejected: username already exists")
		return &authv1.RegisterResponse{
			Success: false,
		}, domain.ErrConflict
	}

	// Hash password
	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		log.Error("error hashing password", "err", err)
		return &authv1.RegisterResponse{
			Success: false,
		}, domain.ErrInternal
	}

	birthdate, err := validation.ValidateDate(req.Birthdate)

	if err != nil {
		log.Warn("failed validating birthdate", "err", err)
		return &authv1.RegisterResponse{Success: false}, err
	}

	// Create user
	user := domain.User{
		Username: req.Username,
		Password: hashedPassword,
		Birthday: birthdate,
		Email:    req.Email,
	}

	createdUser, err := s.repo.CreateUser(ctx, user)
	if err != nil {
		log.Error("error creating user", "err", err)
		return &authv1.RegisterResponse{
			Success: false,
		}, domain.ErrInternal
	}

	log.Info("registration successful", "user_id", createdUser.ID)
	return &authv1.RegisterResponse{
		Success: true,
		UserId:  int32(createdUser.ID),
	}, nil
}

// Login authenticates user and issues JWT tokens
func (s *PublicIdentityService) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	log := publicServiceLogger(ctx).With("operation", "login")

	log.Info("login attempt", "identifier", req.Usernameoremail)

	var user domain.User
	var err error

	if validation.ValidateEmail(req.Usernameoremail) == nil {
		user, err = s.repo.GetUserByEmail(ctx, req.Usernameoremail)
	} else if validation.ValidateUsername(req.Usernameoremail) == nil {
		user, err = s.repo.GetUserByUsername(ctx, req.Usernameoremail)
	} else {
		log.Warn("invalid login identifier")
		return nil, domain.ErrBadRequest
	}

	if err != nil {
		log.Warn("login user lookup failed", "err", err)
		return nil, err
	}

	if !VerifyPassword(req.Password, user.Password) {
		log.Warn("login password verification failed")
		return nil, domain.ErrUnauthorized
	}

	token, err := s.tokens.IssueTokens(ctx, strconv.Itoa(int(user.ID)))
	if err != nil {
		log.Error("error issuing tokens", "err", err)
		return nil, domain.ErrInternal
	}

	log.Info("login successful", "user_id", user.ID)
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
	log := publicServiceLogger(ctx).With("operation", "refresh_login")
	log.Info("refresh login attempt")

	claims, err := s.tokens.ParseRefresh(req.RefreshToken)
	if err != nil {
		log.Warn("invalid refresh token", "err", err)
		return nil, domain.ErrUnauthorized
	}

	// Make sure the refresh token's user + session are still valid.
	ok, err := s.tokens.ValidateToken(ctx, claims)
	if err != nil {
		log.Warn("error validating refresh token", "err", err)
		return nil, domain.ErrUnauthorized
	}

	if !ok {
		log.Warn(
			"Refresh token is revoked or session is no longer valid",
			"user_id", claims.Subject,
			"session_id", claims.SessionID,
		)
		return nil, domain.ErrUnauthorized
	}

	// Issue new tokens for the EXISTING session.
	newTokens, err := s.tokens.IssueTokensForSession(
		ctx,
		claims.Subject,
		claims.SessionID,
	)

	if err != nil {
		log.Error("error refreshing tokens", "err", err)
		return nil, domain.ErrInternal
	}

	log.Info(
		"Refresh successful",
		"user_id", claims.Subject,
		"session_id", claims.SessionID,
	)

	userid, err := strconv.Atoi(claims.Subject)
	if err != nil {
		return nil, domain.ErrInternal
	}

	return &authv1.LoginResponse{
		AccessToken:  newTokens.Access,
		RefreshToken: newTokens.Refresh,
		UserId:       int32(userid),
		Message:      "login successful",
	}, nil
}

func (s *PublicIdentityService) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	log := publicServiceLogger(ctx).With("operation", "logout")

	log.Info("logout attempt")

	err := s.tokens.RevokeSession(ctx, req.SessionId)

	if err != nil {
		log.Error("error revoking tokens", "err", err)
		return nil, domain.ErrInternal
	}

	log.Info("logout successful")

	return &authv1.LogoutResponse{
		Message: "logged out successfully",
	}, nil
}

func (s *PublicIdentityService) LogoutAll(ctx context.Context, req *authv1.LogoutAllRequest) (*authv1.LogoutResponse, error) {
	log := publicServiceLogger(ctx).With("operation", "logout_all")
	log.Info("logout all attempt", "user_id", req.UserId)

	err := s.tokens.RevokeAllTokens(ctx, strconv.Itoa(int(req.UserId)))

	if err != nil {
		log.Error("error revoking tokens", "err", err)
		return nil, domain.ErrInternal
	}

	log.Info("logout all successful", "user_id", req.UserId)

	return &authv1.LogoutResponse{
		Message: "logged out successfully",
	}, nil
}

func (s *PublicIdentityService) GetUserByID(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	log := publicServiceLogger(ctx).With("operation", "get_user_by_id")
	log.Debug("user lookup attempt", "user_id", req.Id)
	user, err := s.repo.GetUserByID(ctx, int(req.Id))

	if err != nil {
		log.Warn("user lookup failed", "user_id", req.Id, "err", err)
		return &authv1.GetUserResponse{}, err
	}

	log.Debug("user lookup successful", "user_id", user.ID)
	return &authv1.GetUserResponse{
		Id:        int32(user.ID),
		Username:  user.Username,
		Email:     user.Email,
		Birthdate: user.Birthday.String(),
	}, nil
}

func (s *PublicIdentityService) GetUserByEmail(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	log := publicServiceLogger(ctx).With("operation", "get_user_by_email")
	log.Debug("user lookup attempt")
	user, err := s.repo.GetUserByEmail(ctx, req.Email)

	if err != nil {
		log.Warn("user lookup failed", "err", err)
		return &authv1.GetUserResponse{}, err
	}

	log.Debug("user lookup successful", "user_id", user.ID)
	return &authv1.GetUserResponse{
		Id:        int32(user.ID),
		Username:  user.Username,
		Email:     user.Email,
		Birthdate: user.Birthday.String(),
	}, nil
}

func (s *PublicIdentityService) GetUserByUsername(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	log := publicServiceLogger(ctx).With("operation", "get_user_by_username")
	log.Debug("user lookup attempt", "username", req.Username)
	user, err := s.repo.GetUserByUsername(ctx, req.Username)

	if err != nil {
		log.Warn("user lookup failed", "err", err)
		return &authv1.GetUserResponse{}, err
	}

	log.Debug("user lookup successful", "user_id", user.ID)
	return &authv1.GetUserResponse{
		Id:        int32(user.ID),
		Username:  user.Username,
		Email:     user.Email,
		Birthdate: user.Birthday.String(),
	}, nil
}

func (s *PublicIdentityService) UpdateUser(ctx context.Context, req *authv1.UpdateUserRequest) (*authv1.UpdateUserResponse, error) {
	log := publicServiceLogger(ctx).With("operation", "update_user")
	log.Info("user update attempt", "user_id", req.UserId)

	tochange, err := s.repo.GetUserByID(ctx, int(req.UserId))
	if err != nil {
		log.Warn("user update target lookup failed", "user_id", req.UserId, "err", err)
		return &authv1.UpdateUserResponse{Success: false}, err
	}

	tochange.Username = req.Username
	tochange.Email = req.Email
	tochange.Birthday, err = validation.ValidateDate(req.Birthdate)

	if err != nil {
		log.Warn("failed validating birthdate", "err", err)
		return &authv1.UpdateUserResponse{Success: false}, err
	}

	err = s.repo.UpdateUser(ctx, int(req.UserId), tochange)

	if err != nil {
		log.Error("failed updating user", "user_id", req.UserId, "err", err)
		return &authv1.UpdateUserResponse{Success: false}, err
	}

	log.Info("user update successful", "user_id", req.UserId)
	return &authv1.UpdateUserResponse{Success: true}, nil
}

func (s *PublicIdentityService) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {
	log := publicServiceLogger(ctx).With("operation", "change_password")
	log.Info("password change attempt", "user_id", req.UserId)
	tochange, err := s.repo.GetUserByID(ctx, int(req.UserId))

	if err != nil {
		log.Warn("password change target lookup failed", "user_id", req.UserId, "err", err)
		return &authv1.ChangePasswordResponse{Success: false}, err
	}

	if !VerifyPassword(req.CurrentPassword, tochange.Password) {
		log.Warn("password verification failed", "user_id", req.UserId)
		return &authv1.ChangePasswordResponse{Success: false}, domain.ErrUnauthorized
	}

	pass, err := HashPassword(req.NewPassword)

	if err != nil {
		log.Error("failed while hashing password", "user_id", req.UserId)
		return &authv1.ChangePasswordResponse{Success: false}, domain.ErrInternal
	}

	err = s.repo.UpdatePassword(ctx, int(req.UserId), pass)

	if err != nil {
		log.Error("failed updating password", "user_id", req.UserId, "err", err)
		return &authv1.ChangePasswordResponse{Success: false}, err
	}

	if err := s.tokens.RevokeAllTokens(ctx, strconv.Itoa(int(req.UserId))); err != nil {
		log.Error("failed to revoke sessions after password change", "user_id", req.UserId, "err", err)
		return &authv1.ChangePasswordResponse{Success: false}, domain.ErrInternal
	}

	log.Info("password change successful", "user_id", req.UserId)
	return &authv1.ChangePasswordResponse{Success: true}, nil
}

func (s *PublicIdentityService) DeleteUser(ctx context.Context, req *authv1.DeleteUserRequest) (*authv1.DeleteUserResponse, error) {
	log := publicServiceLogger(ctx).With("operation", "delete_user")
	log.Info("user deletion attempt", "user_id", req.UserId)
	_, err := s.repo.GetUserByID(ctx, int(req.UserId))

	if err != nil {
		log.Warn("user deletion target lookup failed", "user_id", req.UserId, "err", err)
		return &authv1.DeleteUserResponse{Success: false}, err
	}

	err = s.repo.DeleteUser(ctx, int(req.UserId))

	if err != nil {
		log.Error("user deletion failed", "user_id", req.UserId, "err", err)
		return &authv1.DeleteUserResponse{Success: false}, err
	}

	log.Info("user deletion successful", "user_id", req.UserId)
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
