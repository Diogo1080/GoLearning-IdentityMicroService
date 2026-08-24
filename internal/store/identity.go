package store

import (
	entities "GoLearning-IdentityMicroService/internal/domain"
	"database/sql"
)

type IdentityRepository interface {
	GetUserByEmail(email string) (entities.User, error)
	GetUserByUsername(username string) (entities.User, error)
	GetUserByID(id int) (entities.User, error)
	CreateUser(user entities.User) (entities.User, error)
	UpdatePassword(id int, password string) error
}

type SQLiteIdentityRepository struct {
	DB *sql.DB
}

func NewSQLiteIdentityRepository(db *sql.DB) *SQLiteIdentityRepository {
	return &SQLiteIdentityRepository{DB: db}
}

func (r *SQLiteIdentityRepository) GetUserByEmail(usernameoremail string) (entities.User, error) {
	var user entities.User
	err := r.DB.QueryRow(
		"SELECT id, username, password FROM users WHERE email = $1",
		usernameoremail,
	).Scan(&user.ID, &user.Username, &user.Password)

	if err == sql.ErrNoRows {
		return entities.User{}, entities.ErrNotFound
	}
	return user, err
}

func (r *SQLiteIdentityRepository) GetUserByUsername(usernameoremail string) (entities.User, error) {
	var user entities.User
	err := r.DB.QueryRow(
		"SELECT id, username, password FROM users WHERE username = $1",
		usernameoremail,
	).Scan(&user.ID, &user.Username, &user.Password)

	if err == sql.ErrNoRows {
		return entities.User{}, entities.ErrNotFound
	}
	return user, err
}

func (r *SQLiteIdentityRepository) GetUserByID(id int) (entities.User, error) {
	var user entities.User
	err := r.DB.QueryRow(
		"SELECT id, username, password FROM users WHERE id = $1",
		id,
	).Scan(&user.ID, &user.Username, &user.Password)

	if err == sql.ErrNoRows {
		return entities.User{}, sql.ErrNoRows
	}
	return user, err
}

func (r *SQLiteIdentityRepository) CreateUser(user entities.User) (entities.User, error) {
	result, err := r.DB.Exec(
		"INSERT INTO users (username, password) VALUES ($1, $2)",
		user.Username, user.Password,
	)
	if err != nil {
		return entities.User{}, err
	}

	id, _ := result.LastInsertId()
	user.ID = int64(id)
	return user, nil
}

func (r *SQLiteIdentityRepository) UpdatePassword(id int, hashedPassword string) error {
	_, err := r.DB.Exec(
		"UPDATE users SET password = $1 WHERE id = $2",
		hashedPassword, id,
	)
	return err
}
