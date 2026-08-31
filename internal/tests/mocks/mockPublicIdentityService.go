// internal/service/mock_public_identity_service.go
package mocks

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	"GoLearning-IdentityMicroService/internal/store"
	"context"
	"log/slog"
)

// MockPublicIdentityService implements PublicIdentityService interface for testing
type MockPublicIdentityService struct {
	authv1.UnimplementedPublicIdentityServiceServer
	repo   store.IdentityRepository
	rds    *store.Redis
	logger *slog.Logger

	RegisterFunc          func(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error)
	LoginFunc             func(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error)
	GetUserByEmailFunc    func(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error)
	GetUserByUsernameFunc func(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error)
	GetUserByIDFunc       func(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error)
	UpdateUserFunc        func(ctx context.Context, req *authv1.UpdateUserRequest) (*authv1.UpdateUserResponse, error)
	ChangePasswordFunc    func(ctx context.Context, req *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error)
	DeleteUserFunc        func(ctx context.Context, req *authv1.DeleteUserRequest) (*authv1.DeleteUserResponse, error)
	LogoutFunc            func(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error)
}

func (m *MockPublicIdentityService) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	if m.RegisterFunc == nil {
		panic("RegisterFunc not implemented")
	}
	return m.RegisterFunc(ctx, req)
}

func (m *MockPublicIdentityService) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	if m.LoginFunc == nil {
		panic("LoginFunc not implemented")
	}
	return m.LoginFunc(ctx, req)
}

func (m *MockPublicIdentityService) GetUserByEmail(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	if m.GetUserByEmailFunc == nil {
		panic("GetUserByEmailFunc not implemented")
	}
	return m.GetUserByEmailFunc(ctx, req)
}

func (m *MockPublicIdentityService) GetUserByUsername(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	if m.GetUserByUsernameFunc == nil {
		panic("GetUserByUsernameFunc not implemented")
	}
	return m.GetUserByUsernameFunc(ctx, req)
}

func (m *MockPublicIdentityService) GetUserByID(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	if m.GetUserByIDFunc == nil {
		panic("GetUserByIDFunc not implemented")
	}
	return m.GetUserByIDFunc(ctx, req)
}

func (m *MockPublicIdentityService) UpdateUser(ctx context.Context, req *authv1.UpdateUserRequest) (*authv1.UpdateUserResponse, error) {
	if m.UpdateUserFunc == nil {
		panic("UpdateUserFunc not implemented")
	}
	return m.UpdateUserFunc(ctx, req)
}

func (m *MockPublicIdentityService) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {
	if m.ChangePasswordFunc == nil {
		panic("ChangePasswordFunc not implemented")
	}
	return m.ChangePasswordFunc(ctx, req)
}

func (m *MockPublicIdentityService) DeleteUser(ctx context.Context, req *authv1.DeleteUserRequest) (*authv1.DeleteUserResponse, error) {
	if m.DeleteUserFunc == nil {
		panic("DeleteUserFunc not implemented")
	}
	return m.DeleteUserFunc(ctx, req)
}

func (m *MockPublicIdentityService) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	if m.LogoutFunc == nil {
		panic("LogoutFunc not implemented")
	}
	return m.LogoutFunc(ctx, req)
}
