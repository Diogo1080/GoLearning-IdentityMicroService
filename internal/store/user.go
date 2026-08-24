package store

import (
	entities "GoLearning-IdentityMicroService/internal/domain"
	"database/sql"
)

type SQLiteUserRepository struct {
	DB *sql.DB
}

func NewSQLiteUserRepository(db *sql.DB) *SQLiteUserRepository {
	return &SQLiteUserRepository{DB: db}
}

func (r *SQLiteUserRepository) GetUserByUsername(username string) (entities.User, error) {
	result, err := r.DB.Query("SELECT id, username, password FROM users WHERE username = $1", username)
	if err != nil {
		return entities.User{}, err
	}

	defer result.Close()

	if result.Next() {
		var user entities.User
		err := result.Scan(&user.ID, &user.Username, &user.Password)
		if err != nil {
			return entities.User{}, err
		}
		return user, nil
	}

	return entities.User{}, entities.ErrNotFound
}

func (r *SQLiteUserRepository) GetUserByID(id int) (entities.User, error) {
	result, err := r.DB.Query("SELECT id, username, password FROM users WHERE id = $1", id)
	if err != nil {
		return entities.User{}, err
	}

	defer result.Close()

	if result.Next() {
		var user entities.User
		err := result.Scan(&user.ID, &user.Username, &user.Password)
		if err != nil {
			return entities.User{}, err
		}
		return user, nil
	}

	return entities.User{}, entities.ErrNotFound
}

func (r *SQLiteUserRepository) UpdateUser(user entities.User, id int) (entities.User, error) {
	result, err := r.DB.Exec("UPDATE users SET password = $1 WHERE id = $2",
		user.Password, id)
	if err != nil {
		return entities.User{}, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return entities.User{}, err
	}

	if rowsAffected == 0 {
		return entities.User{}, entities.ErrNotFound
	}

	return user, nil
}

func (r *SQLiteUserRepository) DeleteUser(id int) error {

	_, err := r.DB.Exec("DELETE FROM users WHERE id = $1", id)

	if err != nil {
		return err
	}

	return nil
}
