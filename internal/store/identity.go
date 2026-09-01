package store

import (
	entities "GoLearning-IdentityMicroService/internal/domain"
	"GoLearning-IdentityMicroService/internal/logger"
	"database/sql"
	"log/slog"
)

type IdentityRepository interface {
	GetUserByEmail(email string) (entities.User, error)
	GetUserByUsername(username string) (entities.User, error)
	GetUserByID(id int) (entities.User, error)
	CreateUser(user entities.User) (entities.User, error)
	UpdatePassword(id int, hashedPassword string) error
	UpdateUser(id int, userInfo entities.User) error
	DeleteUser(id int) error
}

type SQLiteIdentityRepository struct {
	DB     *sql.DB
	logger *slog.Logger
}

func NewSQLiteIdentityRepository(db *sql.DB) *SQLiteIdentityRepository {
	return &SQLiteIdentityRepository{DB: db, logger: logger.New().WithGroup("Database")}
}

func (r *SQLiteIdentityRepository) GetUserByEmail(email string) (entities.User, error) {
	var user entities.User
	err := r.DB.QueryRow(
		"SELECT id, username,  email, password_hash FROM users WHERE email = $1",
		email,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Password)

	if err == sql.ErrNoRows {
		r.logger.Error("failed to get user", "email", email, "error", err)
		return entities.User{}, entities.ErrNotFound
	}

	return user, err
}

func (r *SQLiteIdentityRepository) GetUserByUsername(username string) (entities.User, error) {
	var user entities.User
	err := r.DB.QueryRow(
		"SELECT id, username, email, password_hash FROM users WHERE username = $1",
		username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Password)

	if err == sql.ErrNoRows {
		r.logger.Error("failed to get user", "username", username, "error", err)
		return entities.User{}, entities.ErrNotFound
	}
	return user, err
}

func (r *SQLiteIdentityRepository) GetUserByID(id int) (entities.User, error) {
	var user entities.User
	err := r.DB.QueryRow(
		"SELECT id, username, email, password_hash FROM users WHERE id = $1",
		id,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Password)

	if err == sql.ErrNoRows {
		r.logger.Error("failed to get user", "id", id, "error", err)
		return entities.User{}, entities.ErrNotFound
	}
	return user, err
}

func (r *SQLiteIdentityRepository) CreateUser(user entities.User) (entities.User, error) {
	//TODO: look into returning postgress
	err := r.DB.QueryRow("INSERT INTO users (username, password_hash, Email, Birthdate) VALUES ($1, $2, $3, $4)  RETURNING id",
		user.Username, user.Password, user.Email, user.Birthday,
	).Scan(&user.ID)

	if err != nil {
		r.logger.Error("failed to insert user", "user", user.ToUserDTO(), "error", err)
		return entities.User{}, err
	}

	return user, nil
}

func (r *SQLiteIdentityRepository) UpdateUser(id int, userInfo entities.User) error {
	result, err := r.DB.Exec("UPDATE users SET username = $1, email=$2, birthdate = $3 WHERE id = $4",
		userInfo.Username, userInfo.Email, userInfo.Birthday, id)

	if err != nil {
		r.logger.Error("failed to update user", "user", userInfo.ToUserDTO(), "error", err)
		return err
	}

	rowsAffected, err := result.RowsAffected()

	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return entities.ErrNotFound
	}

	return nil
}

func (r *SQLiteIdentityRepository) UpdatePassword(id int, hashedPassword string) error {
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

func (r *SQLiteIdentityRepository) DeleteUser(id int) error {

	_, err := r.DB.Exec("DELETE FROM users WHERE id = $1", id)

	if err != nil {
		r.logger.Error("failed to delete user", "id", id, "error", err)
		return err
	}

	return nil
}
