package store

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/lib/pq"
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
	return slog.Default().With("service", "IdentityRepository")
}

func mapDatabaseError(log *slog.Logger, operation string, err error) error {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return domain.ErrNotFound
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	}

	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return domain.ErrConflict
	}

	log.Error("database operation failed", "operation", operation, "error", err)
	return domain.ErrInternal
}

func (r *SQLiteIdentityRepository) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	log := identityStoreLogger(ctx).With("operation", "get_user_by_email")
	var user domain.User
	err := r.DB.QueryRowContext(ctx,
		"SELECT id, username,  email, password_hash FROM users WHERE email = $1",
		email,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Password)

	if err == sql.ErrNoRows {
		log.Warn("user not found", "error", err)
		return domain.User{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.User{}, mapDatabaseError(log, "get_user_by_email", err)
	}

	return user, err
}

func (r *SQLiteIdentityRepository) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	log := identityStoreLogger(ctx).With("operation", "get_user_by_username")
	var user domain.User
	err := r.DB.QueryRowContext(ctx,
		"SELECT id, username, email, password_hash FROM users WHERE username = $1",
		username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Password)

	if err == sql.ErrNoRows {
		log.Warn("user not found", "error", err)
		return domain.User{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.User{}, mapDatabaseError(log, "get_user_by_username", err)
	}
	return user, err
}

func (r *SQLiteIdentityRepository) GetUserByID(ctx context.Context, id int) (domain.User, error) {
	log := identityStoreLogger(ctx).With("operation", "get_user_by_id")
	var user domain.User
	err := r.DB.QueryRowContext(ctx,
		"SELECT id, username, email, password_hash FROM users WHERE id = $1",
		id,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Password)

	if err == sql.ErrNoRows {
		log.Warn("user not found", "user_id", id, "error", err)
		return domain.User{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.User{}, mapDatabaseError(log, "get_user_by_id", err)
	}
	return user, err
}

func (r *SQLiteIdentityRepository) CreateUser(ctx context.Context, user domain.User) (domain.User, error) {
	log := identityStoreLogger(ctx).With("operation", "create_user")
	//TODO: look into returning postgress
	err := r.DB.QueryRowContext(ctx, "INSERT INTO users (username, password_hash, email, birthdate) VALUES ($1, $2, $3, $4) RETURNING id",
		user.Username, user.Password, user.Email, user.Birthday,
	).Scan(&user.ID)

	if err != nil {
		log.Error("failed to insert user", "username", user.Username, "error", err)
		return domain.User{}, mapDatabaseError(log, "create_user", err)
	}

	return user, nil
}

func (r *SQLiteIdentityRepository) UpdateUser(ctx context.Context, id int, userInfo domain.User) error {
	log := identityStoreLogger(ctx).With("operation", "update_user")
	result, err := r.DB.ExecContext(ctx, "UPDATE users SET username = $1, email = $2, birthdate = $3, updated_at = NOW() WHERE id = $4",
		userInfo.Username, userInfo.Email, userInfo.Birthday, id)

	if err != nil {
		log.Error("failed to update user", "user_id", id, "error", err)
		return mapDatabaseError(log, "update_user", err)
	}

	rowsAffected, err := result.RowsAffected()

	if err != nil {
		log.Error("failed to read updated user count", "user_id", id, "error", err)
		return mapDatabaseError(log, "update_user_rows_affected", err)
	}

	if rowsAffected == 0 {
		log.Warn("user not found during update", "user_id", id)
		return domain.ErrNotFound
	}

	return nil
}

func (r *SQLiteIdentityRepository) UpdatePassword(ctx context.Context, id int, hashedPassword string) error {
	log := identityStoreLogger(ctx).With("operation", "update_password")
	result, err := r.DB.ExecContext(ctx,
		"UPDATE users SET password_hash = $1 WHERE id = $2",
		hashedPassword, id,
	)

	if err != nil {
		log.Error("failed to update password", "user_id", id, "error", err)
		return mapDatabaseError(log, "update_password", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return mapDatabaseError(log, "update_password_rows_affected", err)
	}
	if rowsAffected == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func (r *SQLiteIdentityRepository) DeleteUser(ctx context.Context, id int) error {
	log := identityStoreLogger(ctx).With("operation", "delete_user")

	result, err := r.DB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", id)

	if err != nil {
		log.Error("failed to delete user", "user_id", id, "error", err)
		return mapDatabaseError(log, "delete_user", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return mapDatabaseError(log, "delete_user_rows_affected", err)
	}
	if rowsAffected == 0 {
		return domain.ErrNotFound
	}

	return nil
}
