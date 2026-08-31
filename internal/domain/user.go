package domain

import "time"

type User struct {
	ID       int64     `json:"id"`
	Email    string    `json:"email"`
	Username string    `json:"username"`
	Password string    `json:"password"`
	Birthday time.Time `json:"birthday"`
}

type UserDTO struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Birthday string `json:"birthday"`
}

func (u *User) ToUserDTO() UserDTO {
	return UserDTO{
		ID:       int(u.ID),
		Email:    u.Email,
		Username: u.Username,
		Birthday: u.Birthday.String(),
	}
}
