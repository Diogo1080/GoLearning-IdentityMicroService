package store

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/logger"
)

type IdentityRepository interface {
	GetUserByEmail(ctx context.Context, email string) (domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (domain.User, error)
	GetUserByID(ctx context.Context, id int) (domain.User, error)
	CreateUser(ctx context.Context, user domain.User) (domain.User, error)
	UpdatePassword(ctx context.Context, id int, hashedPassword string) error
	UpdateUser(ctx context.Context, id int, userInfo domain.User) error
	DeleteUser(ctx context.Context, id int) error
}

type SQLiteIdentityRepository struct {
	DB     *sql.DB
	logger *slog.Logger
}

func NewSQLiteIdentityRepository(db *sql.DB) *SQLiteIdentityRepository {
	return &SQLiteIdentityRepository{DB: db, logger: logger.New().WithGroup("Database")}
}

func (r *SQLiteIdentityRepository) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	var user domain.User
	err := r.DB.QueryRow(
		"SELECT id, username,  email, password_hash FROM users WHERE email = $1",
		email,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Password)

	if err == sql.ErrNoRows {
		r.logger.Error("failed to get user", "email", email, "error", err)
		return domain.User{}, domain.ErrNotFound
	}

	return user, err
}

func (r *SQLiteIdentityRepository) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	var user domain.User
	err := r.DB.QueryRow(
		"SELECT id, username, email, password_hash FROM users WHERE username = $1",
		username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Password)

	if err == sql.ErrNoRows {
		r.logger.Error("failed to get user", "username", username, "error", err)
		return domain.User{}, domain.ErrNotFound
	}
	return user, err
}

func (r *SQLiteIdentityRepository) GetUserByID(ctx context.Context, id int) (domain.User, error) {
	var user domain.User
	err := r.DB.QueryRow(
		"SELECT id, username, email, password_hash FROM users WHERE id = $1",
		id,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Password)

	if err == sql.ErrNoRows {
		r.logger.Error("failed to get user", "id", id, "error", err)
		return domain.User{}, domain.ErrNotFound
	}
	return user, err
}

func (r *SQLiteIdentityRepository) CreateUser(ctx context.Context, user domain.User) (domain.User, error) {
	//TODO: look into returning postgress
	err := r.DB.QueryRow("INSERT INTO users (username, password_hash, Email, Birthdate) VALUES ($1, $2, $3, $4)  RETURNING id",
		user.Username, user.Password, user.Email, user.Birthday,
	).Scan(&user.ID)

	if err != nil {
		r.logger.Error("failed to insert user", "user", user.ToUserDTO(), "error", err)
		return domain.User{}, err
	}

	return user, nil
}

func (r *SQLiteIdentityRepository) UpdateUser(ctx context.Context, id int, userInfo domain.User) error {
	result, err := r.DB.Exec("UPDATE users SET username = $1, email=$2, birthdate = $3 WHERE id = $4",
		userInfo.Username, userInfo.Email, userInfo.Birthday, id)

	if err != nil {
		r.logger.Error("failed to update user", "user", userInfo.ToUserDTO(), "error", err)
		return domain.ErrConflict
	}

	rowsAffected, err := result.RowsAffected()

	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func (r *SQLiteIdentityRepository) UpdatePassword(ctx context.Context, id int, hashedPassword string) error {
	_, err := r.DB.Exec(
		"UPDATE users SET password_hash = $1 WHERE id = $2",
		hashedPassword, id,
	)

	if err != nil {
		r.logger.Error("failed to update password", "id", id, "error", err)
		return err
	}

	return nil
}

func (r *SQLiteIdentityRepository) DeleteUser(ctx context.Context, id int) error {

	_, err := r.DB.Exec("DELETE FROM users WHERE id = $1", id)

	if err != nil {
		r.logger.Error("failed to delete user", "id", id, "error", err)
		return err
	}

	return nil
}
