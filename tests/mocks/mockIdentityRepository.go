package mocks

import (
	"context"

	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"

	"github.com/stretchr/testify/mock"
)

type MockIdentityRepository struct {
	mock.Mock
}

func (m *MockIdentityRepository) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	args := m.Called(email)

	var user domain.User
	if args.Get(0) != nil {
		user = args.Get(0).(domain.User)
	}

	return user, args.Error(1)
}

func (m *MockIdentityRepository) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	args := m.Called(username)

	var user domain.User
	if args.Get(0) != nil {
		user = args.Get(0).(domain.User)
	}

	return user, args.Error(1)
}

func (m *MockIdentityRepository) GetUserByID(ctx context.Context, id int) (domain.User, error) {
	args := m.Called(id)

	var user domain.User
	if args.Get(0) != nil {
		user = args.Get(0).(domain.User)
	}

	return user, args.Error(1)
}

func (m *MockIdentityRepository) CreateUser(ctx context.Context, user domain.User) (domain.User, error) {
	args := m.Called(user)

	var createdUser domain.User
	if args.Get(0) != nil {
		createdUser = args.Get(0).(domain.User)
	}

	return createdUser, args.Error(1)
}

func (m *MockIdentityRepository) UpdatePassword(ctx context.Context, id int, hashedPassword string) error {
	args := m.Called(id, hashedPassword)
	return args.Error(0)
}

func (m *MockIdentityRepository) UpdateUser(ctx context.Context, id int, userInfo domain.User) error {
	args := m.Called(id, userInfo)
	return args.Error(0)
}

func (m *MockIdentityRepository) DeleteUser(ctx context.Context, id int) error {
	args := m.Called(id)
	return args.Error(0)
}
