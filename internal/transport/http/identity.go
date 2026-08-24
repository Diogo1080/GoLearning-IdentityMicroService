package http

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	entities "GoLearning-IdentityMicroService/internal/domain"
	"errors"
	"strconv"

	"GoLearning-IdentityMicroService/internal/service"
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type IdentityHandler struct {
	identityService *service.PublicIdentityService
}

func NewIdentityHandler(identityService *service.PublicIdentityService) *IdentityHandler {
	return &IdentityHandler{identityService: identityService}
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

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	resp, err := h.identityService.Register(ctx, &authv1.RegisterRequest{
		Username:  input.Username,
		Password:  input.Password,
		Email:     input.Email,
		Birthdate: input.Birthdate,
	})

	if err != nil {
		c.JSON(http.StatusServiceUnavailable, entities.ErrServiceUnavailable)
		return
	}

	if !resp.Success {
		c.JSON(http.StatusConflict, entities.ErrConflict)
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
		c.JSON(http.StatusServiceUnavailable, entities.ErrServiceUnavailable)
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
func (h *IdentityHandler) HandleGetUserByUsername(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, entities.ErrUnauthorized)
		return
	}

	username := c.Param("username")
	if len(username) == 0 {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	user, err := h.identityService.GetUserByUsername(username)
	if err != nil {
		if errors.Is(err, entities.ErrNotFound) {
			c.JSON(http.StatusNotFound, entities.ErrNotFound)
			return
		}
		c.JSON(http.StatusInternalServerError, entities.ErrDatabaseFailed)
		return
	}

	if user.ID != authID {
		c.JSON(http.StatusForbidden, entities.ErrUnauthorized)
		return
	}

	c.JSON(http.StatusOK, user) // Fixed: Was StatusFound (302)
}

func (h *IdentityHandler) HandleGetUserByID(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, entities.ErrUnauthorized)
		return
	}

	id := c.Param("id")

	if token.checkId(id) {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	i, _ := strconv.Atoi(id)

	if i != authID {
		c.JSON(http.StatusForbidden, entities.ErrUnauthorized)
		return
	}

	user, err := h.identityService.GetUserByID(i)
	if err != nil {
		c.JSON(http.StatusInternalServerError, entities.ErrDatabaseFailed)
		return
	}

	c.JSON(http.StatusOK, user) // Fixed: Was StatusFound (302)
}

func (h *IdentityHandler) HandleChangePassword(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, entities.ErrUnauthorized)
		return
	}

	var input struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	resp, err := h.identityService.ChangePassword(ctx, authID, input.CurrentPassword, input.NewPassword)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, entities.ErrServiceUnavailable)
		return
	}

	if !resp.Success {
		c.JSON(http.StatusUnauthorized, gin.H{"error": resp.Error})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password changed successfully"})
}

func (h *IdentityHandler) HandleDeleteUser(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, entities.ErrUnauthorized)
		return
	}

	id := c.Param("id")

	if checkId(id) {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	idint, err := strconv.Atoi(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	if idint != authID {
		c.JSON(http.StatusForbidden, entities.ErrUnauthorized)
		return
	}

	if err := h.identityService.DeleteUser(idint); err != nil {
		c.JSON(http.StatusInternalServerError, entities.ErrDatabaseFailed)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user deleted successfully"})
}

// HandleUpdateProfile updates non-credential fields
func (h *IdentityHandler) HandleUpdateProfile(c *gin.Context) {
	authID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, entities.ErrUnauthorized)
		return
	}

	var input struct {
		Username string `json:"username"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	user := entities.User{
		Username: input.Username,
	}

	updated, err := h.identityService.UpdateUser(user, authID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, entities.ErrDatabaseFailed)
		return
	}

	c.JSON(http.StatusOK, updated)
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

//NO http and jwt required

/*
func (h *IdentityHandler) HandleRefreshToken(c *gin.Context) {
	type RefreshInput struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	var input RefreshInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, entities.ErrBadData)
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	resp, err := h.identityService.RefreshToken(ctx, &authv1.RefreshTokenRequest{RefreshToken: input.RefreshToken})
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, entities.ErrServiceUnavailable)
		return
	}

	if resp == nil {
		c.JSON(http.StatusUnauthorized, entities.ErrUnauthorized)
		return
	}

	h.setAuthCookies(c, resp.AccessToken, resp.RefreshToken)

	c.JSON(http.StatusOK, gin.H{
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
	})
}
*/

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
