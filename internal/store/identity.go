package store

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http/middleware/logger"
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
	DB *sql.DB
}

func NewSQLiteIdentityRepository(db *sql.DB) *SQLiteIdentityRepository {
	return &SQLiteIdentityRepository{DB: db}
}

func identityStoreLogger(ctx context.Context) *slog.Logger {
	return logger.GetLoggerFromContext(ctx).With("service", "IdentityRepository")
}

func (r *SQLiteIdentityRepository) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	log := identityStoreLogger(ctx).With("operation", "get_user_by_email")
	var user domain.User
	err := r.DB.QueryRow(
		"SELECT id, username,  email, password_hash FROM users WHERE email = $1",
		email,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Password)

	if err == sql.ErrNoRows {
		log.Warn("user not found", "error", err)
		return domain.User{}, domain.ErrNotFound
	}

	return user, err
}

func (r *SQLiteIdentityRepository) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	log := identityStoreLogger(ctx).With("operation", "get_user_by_username")
	var user domain.User
	err := r.DB.QueryRow(
		"SELECT id, username, email, password_hash FROM users WHERE username = $1",
		username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Password)

	if err == sql.ErrNoRows {
		log.Warn("user not found", "error", err)
		return domain.User{}, domain.ErrNotFound
	}
	return user, err
}

func (r *SQLiteIdentityRepository) GetUserByID(ctx context.Context, id int) (domain.User, error) {
	log := identityStoreLogger(ctx).With("operation", "get_user_by_id")
	var user domain.User
	err := r.DB.QueryRow(
		"SELECT id, username, email, password_hash FROM users WHERE id = $1",
		id,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Password)

	if err == sql.ErrNoRows {
		log.Warn("user not found", "user_id", id, "error", err)
		return domain.User{}, domain.ErrNotFound
	}
	return user, err
}

func (r *SQLiteIdentityRepository) CreateUser(ctx context.Context, user domain.User) (domain.User, error) {
	log := identityStoreLogger(ctx).With("operation", "create_user")
	//TODO: look into returning postgress
	err := r.DB.QueryRow("INSERT INTO users (username, password_hash, Email, Birthdate) VALUES ($1, $2, $3, $4)  RETURNING id",
		user.Username, user.Password, user.Email, user.Birthday,
	).Scan(&user.ID)

	if err != nil {
		log.Error("failed to insert user", "username", user.Username, "error", err)
		return domain.User{}, err
	}

	return user, nil
}

func (r *SQLiteIdentityRepository) UpdateUser(ctx context.Context, id int, userInfo domain.User) error {
	log := identityStoreLogger(ctx).With("operation", "update_user")
	result, err := r.DB.Exec("UPDATE users SET username = $1, email=$2, birthdate = $3 WHERE id = $4",
		userInfo.Username, userInfo.Email, userInfo.Birthday, id)

	if err != nil {
		log.Error("failed to update user", "user_id", id, "error", err)
		return domain.ErrConflict
	}

	rowsAffected, err := result.RowsAffected()

	if err != nil {
		log.Error("failed to read updated user count", "user_id", id, "error", err)
		return err
	}

	if rowsAffected == 0 {
		log.Warn("user not found during update", "user_id", id)
		return domain.ErrNotFound
	}

	return nil
}

func (r *SQLiteIdentityRepository) UpdatePassword(ctx context.Context, id int, hashedPassword string) error {
	log := identityStoreLogger(ctx).With("operation", "update_password")
	_, err := r.DB.Exec(
		"UPDATE users SET password_hash = $1 WHERE id = $2",
		hashedPassword, id,
	)

	if err != nil {
		log.Error("failed to update password", "user_id", id, "error", err)
		return err
	}

	return nil
}

func (r *SQLiteIdentityRepository) DeleteUser(ctx context.Context, id int) error {
	log := identityStoreLogger(ctx).With("operation", "delete_user")

	_, err := r.DB.Exec("DELETE FROM users WHERE id = $1", id)

	if err != nil {
		log.Error("failed to delete user", "user_id", id, "error", err)
		return err
	}

	return nil
}
