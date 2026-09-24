package http

import (
	"fmt"
	"log/slog"
	"strconv"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/logger"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/validation"

	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type TokenManagerPort interface {
	ClearAuthCookies(ctx *gin.Context)

	GetUserIDFromAccessToken(token string) (string, error)
	GetSessionIDFromAccessToken(token string) (string, error)
}

type identityServicePort interface {
	Register(context.Context, *authv1.RegisterRequest) (*authv1.RegisterResponse, error)
	Login(context.Context, *authv1.LoginRequest) (*authv1.LoginResponse, error)
	RefreshLogin(context.Context, *authv1.RefreshLoginRequest) (*authv1.LoginResponse, error)
	GetUserByID(context.Context, *authv1.GetUserRequest) (*authv1.GetUserResponse, error)
	GetUserByEmail(context.Context, *authv1.GetUserRequest) (*authv1.GetUserResponse, error)
	GetUserByUsername(context.Context, *authv1.GetUserRequest) (*authv1.GetUserResponse, error)
	UpdateUser(context.Context, *authv1.UpdateUserRequest) (*authv1.UpdateUserResponse, error)
	DeleteUser(context.Context, *authv1.DeleteUserRequest) (*authv1.DeleteUserResponse, error)
	ChangePassword(context.Context, *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error)
	Logout(context.Context, *authv1.LogoutRequest) (*authv1.LogoutResponse, error)
	LogoutAll(context.Context, *authv1.LogoutAllRequest) (*authv1.LogoutResponse, error)
}

type IdentityHandler struct {
	identityService identityServicePort
	tokens          TokenManagerPort
	logger          *slog.Logger
}

func NewIdentityHandler(identityService identityServicePort, tokens TokenManagerPort) *IdentityHandler {
	return &IdentityHandler{identityService: identityService, tokens: tokens, logger: logger.New().WithGroup("IdentityHandler")}
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
		c.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	if err := validation.ValidateRegisterRequest(input.Username, input.Email, input.Password, input.Birthdate); err != nil {
		c.JSON(http.StatusBadRequest, domain.ErrBadRequest)
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
		c.JSON(mapDomainError(err))
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "user registered successfully",
		"user_id": resp.UserId,
	})
}

func (h *IdentityHandler) HandleLogin(c *gin.Context) {
	type LoginRequest struct {
		Usernameoremail string `json:"usernameoremail" binding:"required"`
		Password        string `json:"password" binding:"required"`
	}

	var input LoginRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	resp, err := h.identityService.Login(ctx, &authv1.LoginRequest{
		Usernameoremail: input.Usernameoremail,
		Password:        input.Password,
	})

	if err != nil {
		c.JSON(mapDomainError(err))
		return
	}

	if resp == nil {
		c.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
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

func (h *IdentityHandler) HandleRefreshLogin(c *gin.Context) {
	refresh := refreshFromHeader(c)

	if refresh == "" {
		refresh = refreshFromCookie(c)
	}

	if refresh == "" {
		c.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	fmt.Print(refresh)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	resp, err := h.identityService.RefreshLogin(ctx, &authv1.RefreshLoginRequest{
		RefreshToken: refresh,
	})

	fmt.Print(err)
	fmt.Print(resp)

	if err != nil {
		c.JSON(mapDomainError(err))
		return
	}

	if resp == nil {
		c.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
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

func (h *IdentityHandler) HandleGetUserByEmail(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	email := c.Param("email")
	if err := validation.ValidateEmail(email); err != nil {
		c.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	user, err := h.identityService.GetUserByEmail(c, &authv1.GetUserRequest{Email: email})
	if err != nil {
		c.JSON(mapDomainError(err))
		return
	}

	if int(user.Id) != authID {
		c.JSON(http.StatusForbidden, domain.ErrUnauthorized)
		return
	}

	c.JSON(http.StatusOK, user)
}

func (h *IdentityHandler) HandleGetUserByUsername(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	username := c.Param("username")

	if err := validation.ValidateUsername(username); err != nil {
		c.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	user, err := h.identityService.GetUserByUsername(c, &authv1.GetUserRequest{Username: username})
	if err != nil {
		c.JSON(mapDomainError(err))
		return
	}

	if int(user.Id) != authID {
		c.JSON(http.StatusForbidden, domain.ErrUnauthorized)
		return
	}

	c.JSON(http.StatusOK, user)
}

func (h *IdentityHandler) HandleGetUserByID(c *gin.Context) {
	h.logger.Info("Routing to service getUserId")
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	id := c.Param("id")

	if validation.ValidateId(id) {
		c.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	i, _ := strconv.Atoi(id)

	if i != authID {
		c.JSON(http.StatusForbidden, domain.ErrUnauthorized)
		return
	}

	user, err := h.identityService.GetUserByID(c, &authv1.GetUserRequest{Id: int32(authID)})
	if err != nil {
		c.JSON(mapDomainError(err))
		return
	}

	h.logger.Info("Responding")
	c.JSON(http.StatusOK, user)
}

// HandleUpdateUser
func (h *IdentityHandler) HandleUpdateUser(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	var input authv1.UpdateUserRequest

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	updated, err := h.identityService.UpdateUser(c, &authv1.UpdateUserRequest{
		UserId:    int32(authID),
		Username:  input.Username,
		Email:     input.Email,
		Birthdate: input.Birthdate,
	})

	if err != nil {
		c.JSON(mapDomainError(err))
		return
	}

	c.JSON(http.StatusOK, updated)
}

// HandleUpdatePassword
func (h *IdentityHandler) HandleUpdatePassword(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	var input authv1.ChangePasswordRequest

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	updated, err := h.identityService.ChangePassword(c, &authv1.ChangePasswordRequest{
		UserId:          int32(authID),
		CurrentPassword: input.CurrentPassword,
		NewPassword:     input.NewPassword,
	})

	if err != nil {
		c.JSON(mapDomainError(err))
		return
	}

	c.JSON(http.StatusOK, updated)
}

func (h *IdentityHandler) HandleDeleteUser(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	id := c.Param("id")

	if validation.ValidateId(id) {
		c.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	idint, err := strconv.Atoi(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	if idint != authID {
		c.JSON(http.StatusForbidden, domain.ErrUnauthorized)
		return
	}

	if _, err := h.identityService.DeleteUser(c, &authv1.DeleteUserRequest{UserId: int32(authID)}); err != nil {
		c.JSON(mapDomainError(err))
		return
	}

	c.JSON(http.StatusOK, domain.SuccessResponse)
}

func (h *IdentityHandler) HandleLogout(c *gin.Context) {
	token, err := c.Cookie("access_token")

	if err != nil {
		token = bearerFromHeader(c)
	}

	if token == "" {
		c.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	sessionID, err := h.tokens.GetSessionIDFromAccessToken(token)

	if err != nil {
		c.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
	}

	h.tokens.ClearAuthCookies(c)

	_, err = h.identityService.Logout(c, &authv1.LogoutRequest{
		SessionId: sessionID,
	})

	if err != nil {
		c.JSON(mapDomainError(err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "logged out successfully",
	})
}

func (h *IdentityHandler) HandleLogoutAll(c *gin.Context) {
	token, err := c.Cookie("access_token")

	if err != nil {
		token = bearerFromHeader(c)
	}

	userID, err := h.tokens.GetUserIDFromAccessToken(token)
	h.tokens.ClearAuthCookies(c)

	if err != nil {
		h.logger.Info("Failed to get userID from access token", "error", err)
		c.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	id, err := strconv.ParseInt(userID, 10, 32)
	if err != nil {
		h.logger.Info("User ID is invalid", "error", err)
		c.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	_, err = h.identityService.LogoutAll(c, &authv1.LogoutAllRequest{
		UserId: int32(id),
	})

	if err != nil {
		c.JSON(mapDomainError(err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "logged out successfully",
	})
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

func refreshFromCookie(c *gin.Context) string {
	h, err := c.Cookie("refresh_token")
	if err == nil {
		if len(h) > 7 && h[:7] == "Bearer " {
			return h[7:]
		}
	}
	return ""
}

func refreshFromHeader(c *gin.Context) string {
	return c.GetHeader("X-Authorization")
}

func bearerFromCookie(c *gin.Context) string {
	h, err := c.Cookie("access_token")
	if err == nil {
		if len(h) > 7 && h[:7] == "Bearer " {
			return h[7:]
		}
	}
	return ""
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

func clearAuthCookies(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)

	c.SetCookie("access_token", "", -1, "/", "", true, true)
	c.SetCookie("refresh_token", "", -1, "/", "", true, true)
}
