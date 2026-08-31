package http

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"GoLearning-IdentityMicroService/internal/logger"
	"GoLearning-IdentityMicroService/internal/validation"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type identityServicePort interface {
	Register(context.Context, *authv1.RegisterRequest) (*authv1.RegisterResponse, error)
	Login(context.Context, *authv1.LoginRequest) (*authv1.LoginResponse, error)
	GetUserByID(context.Context, *authv1.GetUserRequest) (*authv1.GetUserResponse, error)
	GetUserByEmail(context.Context, *authv1.GetUserRequest) (*authv1.GetUserResponse, error)
	GetUserByUsername(context.Context, *authv1.GetUserRequest) (*authv1.GetUserResponse, error)
	UpdateUser(context.Context, *authv1.UpdateUserRequest) (*authv1.UpdateUserResponse, error)
	DeleteUser(context.Context, *authv1.DeleteUserRequest) (*authv1.DeleteUserResponse, error)
	ChangePassword(context.Context, *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error)
	Logout(context.Context, *authv1.LogoutRequest) (*authv1.LogoutResponse, error)
}

type IdentityHandler struct {
	identityService identityServicePort
	logger          *slog.Logger
}

func NewIdentityHandler(identityService identityServicePort) *IdentityHandler {
	return &IdentityHandler{identityService: identityService, logger: logger.New().WithGroup("IdentityHandler")}
}

// HTTP acepted and no jwt required
func (h *IdentityHandler) HandleRegister(c *gin.Context) {
	type RegisterInput struct {
		Username  string `json:"username" binding:"required,min=3,max=50"`
		Password  string `json:"password" binding:"required,min=6"`
		Email     string `json:"email" binding:"required,min=7"`
		Birthdate string `json:"birthdate" binding:"required"`
	}

	var input RegisterInput

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	if err := validation.ValidateRegisterRequest(input.Username, input.Email, input.Password, input.Birthdate); err != nil {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	resp, err := h.identityService.Register(ctx, &authv1.RegisterRequest{
		Username:  input.Username,
		Password:  input.Password,
		Email:     input.Email,
		Birthdate: input.Birthdate,
	})

	if err != nil || !resp.Success {
		if errors.Is(err, entities.ErrAlreadyExists) {
			c.JSON(http.StatusConflict, err)
			return
		}

		c.JSON(http.StatusServiceUnavailable, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "user registered successfully",
		"user_id": resp.UserId,
	})
}

func (h *IdentityHandler) HandleLogin(c *gin.Context) {
	type LoginInput struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	resp, err := h.identityService.Login(ctx, &authv1.LoginRequest{
		Usernameoremail: input.Username,
		Password:        input.Password,
	})

	if err != nil {
		if errors.Is(err, entities.ErrBadData) {
			c.JSON(http.StatusBadRequest, err)
			return
		}
		if errors.Is(err, entities.ErrNotFound) {
			c.JSON(http.StatusNotFound, err)
			return
		}
		if errors.Is(err, entities.ErrUnauthorized) {
			c.JSON(http.StatusUnauthorized, err)
			return
		}

		c.JSON(http.StatusServiceUnavailable, err)
		return
	}

	if resp == nil {
		c.JSON(http.StatusUnauthorized, entities.ErrUnauthorized)
		return
	}

	// Set cookies for browser clients
	h.setAuthCookies(c, resp.AccessToken, resp.RefreshToken)

	c.JSON(http.StatusOK, gin.H{
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
		"user_id":       resp.UserId,
		"message":       resp.Message,
	})
}

// HTTP acepted and jwt required

func (h *IdentityHandler) HandleGetUserByEmail(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, entities.ErrUnauthorized)
		return
	}

	email := c.Param("email")
	if err := validation.ValidateEmail(email); err != nil {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	user, err := h.identityService.GetUserByEmail(c, &authv1.GetUserRequest{Email: email})
	if err != nil {
		if errors.Is(err, entities.ErrNotFound) {
			c.JSON(http.StatusNotFound, entities.ErrNotFound)
			return
		}
		c.JSON(http.StatusInternalServerError, entities.ErrDatabaseFailed)
		return
	}

	if int(user.Id) != authID {
		c.JSON(http.StatusForbidden, entities.ErrUnauthorized)
		return
	}

	c.JSON(http.StatusFound, user)
}

func (h *IdentityHandler) HandleGetUserByUsername(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, entities.ErrUnauthorized)
		return
	}

	username := c.Param("username")

	if err := validation.ValidateUsername(username); err != nil {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	user, err := h.identityService.GetUserByUsername(c, &authv1.GetUserRequest{Username: username})
	if err != nil {
		if errors.Is(err, entities.ErrNotFound) {
			c.JSON(http.StatusNotFound, entities.ErrNotFound)
			return
		}
		c.JSON(http.StatusInternalServerError, entities.ErrDatabaseFailed)
		return
	}

	if int(user.Id) != authID {
		c.JSON(http.StatusForbidden, entities.ErrUnauthorized)
		return
	}

	c.JSON(http.StatusFound, user)
}

func (h *IdentityHandler) HandleGetUserByID(c *gin.Context) {
	h.logger.Info("Routing to service getUserId")
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, entities.ErrUnauthorized)
		return
	}

	id := c.Param("id")

	if validation.ValidateId(id) {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	i, _ := strconv.Atoi(id)

	if i != authID {
		c.JSON(http.StatusForbidden, entities.ErrUnauthorized)
		return
	}

	user, err := h.identityService.GetUserByID(c, &authv1.GetUserRequest{Id: int32(authID)})
	if err != nil {
		if errors.Is(err, entities.ErrNotFound) {
			c.JSON(http.StatusNotFound, err)
			return
		}

		h.logger.Error("Error", "error", err)
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	h.logger.Info("Responding")
	c.JSON(http.StatusFound, user)
}

// HandleUpdateUser
func (h *IdentityHandler) HandleUpdateUser(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, entities.ErrUnauthorized)
		return
	}

	var input authv1.UpdateUserRequest

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	updated, err := h.identityService.UpdateUser(c, &authv1.UpdateUserRequest{
		UserId:    int32(authID),
		Username:  input.Username,
		Email:     input.Email,
		Birthdate: input.Birthdate,
	})

	if err != nil {
		if errors.Is(err, entities.ErrNotFound) {
			c.JSON(http.StatusNotFound, err)
			return
		}
		c.JSON(http.StatusInternalServerError, entities.ErrDatabaseFailed)
		return
	}

	c.JSON(http.StatusOK, updated)
}

// HandleUpdatePassword
func (h *IdentityHandler) HandleUpdatePassword(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, entities.ErrUnauthorized)
		return
	}

	var input authv1.ChangePasswordRequest

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	updated, err := h.identityService.ChangePassword(c, &authv1.ChangePasswordRequest{
		UserId:          int32(authID),
		CurrentPassword: input.CurrentPassword,
		NewPassword:     input.NewPassword,
	})

	if err != nil {
		if errors.Is(err, entities.ErrNotFound) {
			c.JSON(http.StatusNotFound, err)
			return
		}
		c.JSON(http.StatusInternalServerError, entities.ErrDatabaseFailed)
		return
	}

	c.JSON(http.StatusOK, updated)
}

func (h *IdentityHandler) HandleDeleteUser(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, entities.ErrUnauthorized)
		return
	}

	id := c.Param("id")

	if validation.ValidateId(id) {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	idint, err := strconv.Atoi(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	fmt.Print(authID, idint)
	if idint != authID {
		c.JSON(http.StatusForbidden, entities.ErrUnauthorized)
		return
	}

	if _, err := h.identityService.DeleteUser(c, &authv1.DeleteUserRequest{UserId: int32(authID)}); err != nil {
		if errors.Is(err, entities.ErrNotFound) {
			c.JSON(http.StatusNotFound, err)
			return
		}
		c.JSON(http.StatusInternalServerError, entities.ErrDatabaseFailed)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user deleted successfully"})
}

func (h *IdentityHandler) HandleLogout(c *gin.Context) {
	token, _ := c.Cookie("access_token")
	if token == "" {
		token = bearerFromHeader(c)
	}

	if token == "" {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	_, err := h.identityService.Logout(ctx, &authv1.LogoutRequest{Token: token})
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, entities.ErrServiceUnavailable)
		return
	}

	// Clear cookies
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("access_token", "", -1, "/", "", true, true)
	c.SetCookie("refresh_token", "", -1, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

// Helper functions
func (h *IdentityHandler) setAuthCookies(c *gin.Context, accessToken, refreshToken string) {
	// Calculate expiry times (matching auth service JWT expiry)
	expAcc := 15 * 60          // 15 minutes
	expRef := 7 * 24 * 60 * 60 // 7 days

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("access_token", accessToken, expAcc, "/", "", true, true)
	c.SetCookie("refresh_token", refreshToken, expRef, "/", "", true, true)
}

func bearerFromHeader(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if len(h) > 7 && h[:7] == "Bearer " {
		return h[7:]
	}
	return ""
}

func getUserID(c *gin.Context) (int, bool) {
	val, exists := c.Get("userID")
	if !exists {
		return 0, false
	}
	if userID, ok := val.(int32); ok {
		return int(userID), true
	}
	return 0, false
}
