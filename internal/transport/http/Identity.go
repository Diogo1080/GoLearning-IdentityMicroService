package http

import (
	"log/slog"
	"strconv"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/domain"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http/middleware/logger"
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
}

func NewIdentityHandler(identityService identityServicePort, tokens TokenManagerPort) *IdentityHandler {
	return &IdentityHandler{identityService: identityService, tokens: tokens}
}

func handlerLogger(ctx *gin.Context) *slog.Logger {
	return logger.GetLoggerFromContext(ctx.Request.Context()).With("component", "IdentityHandler")
}

// HTTP acepted and no jwt required
func (h *IdentityHandler) HandleRegister(ctx *gin.Context) {
	log := handlerLogger(ctx).With("operation", "register")
	log.Info("register request received")
	type RegisterInput struct {
		Username  string `json:"username" binding:"required,min=3,max=50"`
		Password  string `json:"password" binding:"required,min=6"`
		Email     string `json:"email" binding:"required,min=7"`
		Birthdate string `json:"birthdate" binding:"required"`
	}

	var input RegisterInput

	if err := ctx.ShouldBindJSON(&input); err != nil {
		log.Warn("register request binding failed", "err", err)
		ctx.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	if err := validation.ValidateRegisterRequest(input.Username, input.Email, input.Password, input.Birthdate); err != nil {
		log.Warn("register request validation failed", "err", err)
		ctx.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	c, cancel := context.WithTimeout(ctx.Request.Context(), 5*time.Second)
	defer cancel()

	resp, err := h.identityService.Register(c, &authv1.RegisterRequest{
		Username:  input.Username,
		Password:  input.Password,
		Email:     input.Email,
		Birthdate: input.Birthdate,
	})

	if err != nil || !resp.Success {
		log.Warn("register service failed", "err", err)
		ctx.JSON(mapDomainError(err))
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{
		"message": "user registered successfully",
		"user_id": resp.UserId,
	})
	log.Info("register request completed", "user_id", resp.UserId)
}

func (h *IdentityHandler) HandleLogin(ctx *gin.Context) {
	log := handlerLogger(ctx).With("operation", "login")
	log.Info("login request received")
	type LoginRequest struct {
		Usernameoremail string `json:"usernameoremail" binding:"required"`
		Password        string `json:"password" binding:"required"`
	}

	var input LoginRequest
	if err := ctx.ShouldBindJSON(&input); err != nil {
		log.Warn("login request binding failed", "err", err)
		ctx.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	c, cancel := context.WithTimeout(ctx.Request.Context(), 5*time.Second)
	defer cancel()

	resp, err := h.identityService.Login(c, &authv1.LoginRequest{
		Usernameoremail: input.Usernameoremail,
		Password:        input.Password,
	})

	if err != nil {
		log.Warn("login service failed", "err", err)
		ctx.JSON(mapDomainError(err))
		return
	}

	if resp == nil {
		log.Warn("login returned no response")
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	// Set cookies for browser clients
	h.setAuthCookies(ctx, resp.AccessToken, resp.RefreshToken)

	ctx.JSON(http.StatusOK, gin.H{
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
		"user_id":       resp.UserId,
		"message":       resp.Message,
	})
	log.Info("login request completed", "user_id", resp.UserId)
}

func (h *IdentityHandler) HandleRefreshLogin(ctx *gin.Context) {
	log := handlerLogger(ctx).With("operation", "refresh_login")
	log.Info("refresh login request received")
	refresh := refreshFromHeader(ctx)

	if refresh == "" {
		log.Warn("refresh login request missing token")
		refresh = refreshFromCookie(ctx)
	}

	if refresh == "" {
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	c, cancel := context.WithTimeout(ctx.Request.Context(), 5*time.Second)
	defer cancel()

	resp, err := h.identityService.RefreshLogin(c, &authv1.RefreshLoginRequest{
		RefreshToken: refresh,
	})

	if err != nil {
		log.Warn("refresh login service failed", "err", err)
		ctx.JSON(mapDomainError(err))
		return
	}

	if resp == nil {
		log.Warn("refresh login returned no response")
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	// Set cookies for browser clients
	h.setAuthCookies(ctx, resp.AccessToken, resp.RefreshToken)

	ctx.JSON(http.StatusOK, gin.H{
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
		"user_id":       resp.UserId,
		"message":       resp.Message,
	})
	log.Info("refresh login request completed", "user_id", resp.UserId)
}

func (h *IdentityHandler) HandleGetUserByEmail(ctx *gin.Context) {
	authID, ok := getUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	email := ctx.Param("email")
	if err := validation.ValidateEmail(email); err != nil {
		ctx.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	user, err := h.identityService.GetUserByEmail(ctx, &authv1.GetUserRequest{Email: email})
	if err != nil {
		ctx.JSON(mapDomainError(err))
		return
	}

	if int(user.Id) != authID {
		ctx.JSON(http.StatusForbidden, domain.ErrUnauthorized)
		return
	}

	ctx.JSON(http.StatusOK, user)
}

func (h *IdentityHandler) HandleGetUserByUsername(ctx *gin.Context) {
	authID, ok := getUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	username := ctx.Param("username")

	if err := validation.ValidateUsername(username); err != nil {
		ctx.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	user, err := h.identityService.GetUserByUsername(ctx, &authv1.GetUserRequest{Username: username})
	if err != nil {
		ctx.JSON(mapDomainError(err))
		return
	}

	if int(user.Id) != authID {
		ctx.JSON(http.StatusForbidden, domain.ErrUnauthorized)
		return
	}

	ctx.JSON(http.StatusOK, user)
}

func (h *IdentityHandler) HandleGetUserByID(ctx *gin.Context) {
	log := handlerLogger(ctx).With("operation", "get_user_by_id")

	log.Debug("user lookup request received")
	authID, ok := getUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	id := ctx.Param("id")

	if validation.ValidateId(id) {
		ctx.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	i, _ := strconv.Atoi(id)

	if i != authID {
		ctx.JSON(http.StatusForbidden, domain.ErrUnauthorized)
		return
	}

	user, err := h.identityService.GetUserByID(ctx, &authv1.GetUserRequest{Id: int32(authID)})
	if err != nil {
		ctx.JSON(mapDomainError(err))
		return
	}

	log.Debug("user lookup request completed", "user_id", authID)
	ctx.JSON(http.StatusOK, user)
}

func (h *IdentityHandler) HandleGetCurrentUser(ctx *gin.Context) {
	log := handlerLogger(ctx).With("operation", "get_current_user")
	log.Debug("current user request received")
	authID, ok := getUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	user, err := h.identityService.GetUserByID(ctx, &authv1.GetUserRequest{Id: int32(authID)})
	if err != nil {
		log.Warn("current user lookup failed", "user_id", authID, "err", err)
		ctx.JSON(mapDomainError(err))
		return
	}

	ctx.JSON(http.StatusOK, user)
	log.Debug("current user request completed", "user_id", authID)
}

// HandleUpdateUser
func (h *IdentityHandler) HandleUpdateUser(ctx *gin.Context) {
	log := handlerLogger(ctx).With("operation", "update_user")
	log.Info("user update request received")
	authID, ok := getUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	var input authv1.UpdateUserRequest

	if err := ctx.ShouldBindJSON(&input); err != nil {
		log.Warn("user update request binding failed", "err", err)
		ctx.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	updated, err := h.identityService.UpdateUser(ctx, &authv1.UpdateUserRequest{
		UserId:    int32(authID),
		Username:  input.Username,
		Email:     input.Email,
		Birthdate: input.Birthdate,
	})

	if err != nil {
		log.Warn("user update service failed", "user_id", authID, "err", err)
		ctx.JSON(mapDomainError(err))
		return
	}

	ctx.JSON(http.StatusOK, updated)
	log.Info("user update request completed", "user_id", authID)
}

// HandleUpdatePassword
func (h *IdentityHandler) HandleUpdatePassword(ctx *gin.Context) {
	log := handlerLogger(ctx).With("operation", "change_password")
	log.Info("password change request received")
	authID, ok := getUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	var input authv1.ChangePasswordRequest

	if err := ctx.ShouldBindJSON(&input); err != nil {
		log.Warn("password change request binding failed", "err", err)
		ctx.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	updated, err := h.identityService.ChangePassword(ctx, &authv1.ChangePasswordRequest{
		UserId:          int32(authID),
		CurrentPassword: input.CurrentPassword,
		NewPassword:     input.NewPassword,
	})

	if err != nil {
		log.Warn("password change service failed", "user_id", authID, "err", err)
		ctx.JSON(mapDomainError(err))
		return
	}

	ctx.JSON(http.StatusOK, updated)
	log.Info("password change request completed", "user_id", authID)
}

func (h *IdentityHandler) HandleDeleteUser(ctx *gin.Context) {
	log := handlerLogger(ctx).With("operation", "delete_user")
	log.Info("user deletion request received")
	authID, ok := getUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	id := ctx.Param("id")

	if validation.ValidateId(id) {
		ctx.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	idint, err := strconv.Atoi(id)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, domain.ErrBadRequest)
		return
	}

	if idint != authID {
		ctx.JSON(http.StatusForbidden, domain.ErrUnauthorized)
		return
	}

	if _, err := h.identityService.DeleteUser(ctx, &authv1.DeleteUserRequest{UserId: int32(authID)}); err != nil {
		log.Warn("user deletion service failed", "user_id", authID, "err", err)
		ctx.JSON(mapDomainError(err))
		return
	}

	ctx.JSON(http.StatusOK, domain.SuccessResponse)
	log.Info("user deletion request completed", "user_id", authID)
}

func (h *IdentityHandler) HandleLogout(ctx *gin.Context) {
	log := handlerLogger(ctx).With("operation", "logout")
	log.Info("logout request received")
	token, err := ctx.Cookie("access_token")

	if err != nil {
		token = bearerFromHeader(ctx)
	}

	if token == "" {
		log.Warn("logout request missing access token")
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	sessionID, err := h.tokens.GetSessionIDFromAccessToken(token)

	if err != nil {
		log.Warn("logout access token invalid", "err", err)
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
	}

	h.tokens.ClearAuthCookies(ctx)

	_, err = h.identityService.Logout(ctx, &authv1.LogoutRequest{
		SessionId: sessionID,
	})

	if err != nil {
		log.Warn("logout service failed", "err", err)
		ctx.JSON(mapDomainError(err))
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "logged out successfully",
	})
	log.Info("logout request completed")
}

func (h *IdentityHandler) HandleLogoutAll(ctx *gin.Context) {
	log := handlerLogger(ctx).With("operation", "logout_all")
	log.Info("logout all request received")
	token, err := ctx.Cookie("access_token")

	if err != nil {
		token = bearerFromHeader(ctx)
	}

	userID, err := h.tokens.GetUserIDFromAccessToken(token)
	h.tokens.ClearAuthCookies(ctx)

	if err != nil {
		log.Warn("failed to get user ID from access token", "err", err)
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	id, err := strconv.ParseInt(userID, 10, 32)
	if err != nil {
		log.Warn("user ID from access token is invalid", "err", err)
		ctx.JSON(http.StatusUnauthorized, domain.ErrUnauthorized)
		return
	}

	_, err = h.identityService.LogoutAll(ctx, &authv1.LogoutAllRequest{
		UserId: int32(id),
	})

	if err != nil {
		log.Warn("logout all service failed", "err", err)
		ctx.JSON(mapDomainError(err))
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "logged out successfully",
	})
	log.Info("logout all request completed", "user_id", id)
}

// Helper functions
func (h *IdentityHandler) setAuthCookies(ctx *gin.Context, accessToken, refreshToken string) {
	// Calculate expiry times (matching auth service JWT expiry)
	expAcc := 15 * 60          // 15 minutes
	expRef := 7 * 24 * 60 * 60 // 7 days

	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("access_token", accessToken, expAcc, "/", "", true, true)
	ctx.SetCookie("refresh_token", refreshToken, expRef, "/", "", true, true)
}

func refreshFromCookie(ctx *gin.Context) string {
	h, err := ctx.Cookie("refresh_token")
	if err == nil {
		if len(h) > 7 && h[:7] == "Bearer " {
			return h[7:]
		}
	}
	return ""
}

func refreshFromHeader(ctx *gin.Context) string {
	return ctx.GetHeader("X-Authorization")
}

func bearerFromCookie(ctx *gin.Context) string {
	h, err := ctx.Cookie("access_token")
	if err == nil {
		if len(h) > 7 && h[:7] == "Bearer " {
			return h[7:]
		}
	}
	return ""
}

func bearerFromHeader(ctx *gin.Context) string {
	h := ctx.GetHeader("Authorization")
	if len(h) > 7 && h[:7] == "Bearer " {
		return h[7:]
	}
	return ""
}

func getUserID(ctx *gin.Context) (int, bool) {
	val, exists := ctx.Get("userID")
	if !exists {
		return 0, false
	}
	if userID, ok := val.(int32); ok {
		return int(userID), true
	}
	return 0, false
}

func clearAuthCookies(ctx *gin.Context) {
	ctx.SetSameSite(http.SameSiteLaxMode)

	ctx.SetCookie("access_token", "", -1, "/", "", true, true)
	ctx.SetCookie("refresh_token", "", -1, "/", "", true, true)
}
