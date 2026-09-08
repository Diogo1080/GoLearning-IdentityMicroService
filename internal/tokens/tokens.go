package tokens

import (
	entities "GoLearning-IdentityMicroService/internal/domain"
	"GoLearning-IdentityMicroService/internal/store"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	Issuer   = "jwt-todo-app"
	Audience = "jwt-todo-client"

	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

type Claims struct {
	// UserVersion invalidates tokens across ALL sessions for a user.
	UserVersion int64 `json:"userVersion"`

	// SessionVersion inFs tokens for ONE specific session.
	SessionVersion int64 `json:"sessionVersion"`

	// SessionID identifies the login/session this token belongs to.
	SessionID string `json:"sessionId"`

	TokenType string `json:"tokenType"`

	jwt.RegisteredClaims
}

type Tokens struct {
	Access  string
	Refresh string
	ExpAcc  time.Time
	ExpRef  time.Time

	UserID    string
	SessionID string

	UserVersion    int64
	SessionVersion int64

	Issuer   string
	Audience string
}

type TokenManager struct {
	rds *store.Redis
}

func NewTokenManager(rds *store.Redis) *TokenManager {
	return &TokenManager{rds: rds}
}

// IssueTokens creates a new session and issues an access + refresh token pair.
//
// Use this when the user actually logs in.
func (tm *TokenManager) IssueTokens(ctx context.Context, userID string) (*Tokens, error) {
	sessionID := uuid.NewString()

	if err := tm.rds.CreateSession(ctx, sessionID); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	t, err := tm.issueTokensForSession(
		ctx,
		tm.rds,
		userID,
		sessionID,
		1,
	)
	if err != nil {
		_ = tm.rds.RevokeSession(ctx, sessionID)
		return nil, err
	}

	return t, nil
}

// IssueTokensForSession issues new tokens for an EXISTING session.
//
// Use this when refreshing an existing refresh token.
//
// The session ID remains unchanged, so the user stays on the same
// device/session.
func (tm *TokenManager) IssueTokensForSession(ctx context.Context, userID string, sessionID string) (*Tokens, error) {
	sessionVersion, err := tm.rds.GetSessionVersion(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("get session version: %w", err)
	}

	return tm.issueTokensForSession(
		ctx,
		tm.rds,
		userID,
		sessionID,
		sessionVersion+1,
	)
}

// issueTokensForSession creates access + refresh tokens using
// an existing session and version.
func (tm *TokenManager) issueTokensForSession(ctx context.Context, r *store.Redis, userID string, sessionID string, sessionVersion int64) (*Tokens, error) {
	now := time.Now()

	userVersion, err := r.GetUserVersion(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user version: %w", err)
	}

	t := &Tokens{
		UserID:    userID,
		SessionID: sessionID,

		UserVersion:    userVersion,
		SessionVersion: sessionVersion,

		ExpAcc:   now.Add(15 * time.Minute),
		ExpRef:   now.Add(7 * 24 * time.Hour),
		Issuer:   Issuer,
		Audience: Audience,
	}

	accessClaims := Claims{
		UserVersion:    userVersion,
		SessionVersion: sessionVersion,
		SessionID:      sessionID,
		TokenType:      TokenTypeAccess,

		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    Issuer,
			Audience:  jwt.ClaimStrings{Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(t.ExpAcc),
		},
	}

	refreshClaims := Claims{
		UserVersion:    userVersion,
		SessionVersion: sessionVersion,
		SessionID:      sessionID,
		TokenType:      TokenTypeRefresh,

		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    Issuer,
			Audience:  jwt.ClaimStrings{Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(t.ExpRef),
		},
	}

	access := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		accessClaims,
	)

	refresh := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		refreshClaims,
	)

	t.Access, err = access.SignedString(
		[]byte(os.Getenv("ACCESS_SECRET")),
	)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	t.Refresh, err = refresh.SignedString(
		[]byte(os.Getenv("REFRESH_SECRET")),
	)
	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}

	return t, nil
}

func (tm *TokenManager) SetAuthCookies(c *gin.Context, t *Tokens) {
	c.SetSameSite(http.SameSiteLaxMode)

	c.SetCookie(
		"access_token",
		t.Access,
		int(time.Until(t.ExpAcc).Seconds()),
		"/",
		"",
		true,
		true,
	)

	c.SetCookie(
		"refresh_token",
		t.Refresh,
		int(time.Until(t.ExpRef).Seconds()),
		"/",
		"",
		true,
		true,
	)
}

func (tm *TokenManager) ClearAuthCookies(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)

	c.SetCookie(
		"access_token",
		"",
		-1,
		"/",
		"",
		true,
		true,
	)

	c.SetCookie(
		"refresh_token",
		"",
		-1,
		"/",
		"",
		true,
		true,
	)
}

// ParseAccess parses and validates an access token.
func (tm *TokenManager) ParseAccess(tokenStr string) (*Claims, error) {
	secret := os.Getenv("ACCESS_SECRET")

	claims, err := tm.parseWithSecret(tokenStr, secret)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != TokenTypeAccess {
		return nil, entities.ErrUnauthorized
	}

	return claims, nil
}

// ParseRefresh parses and validates a refresh token.
func (tm *TokenManager) ParseRefresh(tokenStr string) (*Claims, error) {
	secret := os.Getenv("REFRESH_SECRET")

	claims, err := tm.parseWithSecret(tokenStr, secret)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != TokenTypeRefresh {
		return nil, entities.ErrUnauthorized
	}

	return claims, nil
}

func (tm *TokenManager) parseWithSecret(tokenStr, secret string) (*Claims, error) {
	if secret == "" {
		return nil, errors.New("jwt secret not configured")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{
			jwt.SigningMethodHS256.Alg(),
		}),
		jwt.WithAudience(Audience),
		jwt.WithIssuer(Issuer),
		jwt.WithLeeway(30*time.Second),
	)

	token, err := parser.ParseWithClaims(
		tokenStr,
		&Claims{},
		func(t *jwt.Token) (interface{}, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("unexpected signing method")
			}

			return []byte(secret), nil
		},
	)

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, entities.ErrUnauthorized
	}

	// These are required for session-aware authentication.
	if claims.Subject == "" {
		return nil, entities.ErrUnauthorized
	}

	if claims.SessionID == "" {
		return nil, entities.ErrUnauthorized
	}

	if claims.UserVersion < 1 {
		return nil, entities.ErrUnauthorized
	}

	if claims.SessionVersion < 1 {
		return nil, entities.ErrUnauthorized
	}

	return claims, nil
}

// ValidateToken checks that BOTH:
//
//  1. The user's global token version matches.
//  2. The session's token version matches.
func (tm *TokenManager) ValidateToken(ctx context.Context, claims *Claims) (bool, error) {
	if claims.Subject == "" {
		return false, errors.New("token subject missing")
	}

	if claims.SessionID == "" {
		return false, errors.New("session ID missing")
	}

	return tm.rds.IsTokenValid(
		ctx,
		claims.Subject,
		claims.SessionID,
		claims.UserVersion,
		claims.SessionVersion,
	)
}

// RevokeSession logs out ONLY the current session.
//
// Other sessions belonging to the same user remain valid.
func (tm *TokenManager) RevokeSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return errors.New("session ID missing")
	}

	if err := tm.rds.RevokeSession(ctx, sessionID); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	return nil
}

// RevokeAllTokens invalidates ALL existing access and refresh tokens
// for the user across every session.
// Therefore every existing token becomes invalid.
func (tm *TokenManager) RevokeAllTokens(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.New("user ID missing")
	}

	_, err := tm.rds.IncrementUserVersion(ctx, userID)
	if err != nil {
		return fmt.Errorf("revoke all user tokens: %w", err)
	}

	return nil
}

// GetUserIDFromAccessToken parses an access token and returns the user ID.
func (tm *TokenManager) GetUserIDFromAccessToken(tokenStr string) (string, error) {
	claims, err := tm.ParseAccess(tokenStr)
	if err != nil {
		return "", err
	}

	return claims.Subject, nil
}

// GetUserIDFromRefreshToken parses a refresh token and returns the user ID.
func (tm *TokenManager) GetUserIDFromRefreshToken(tokenStr string) (string, error) {
	claims, err := tm.ParseRefresh(tokenStr)
	if err != nil {
		return "", err
	}

	return claims.Subject, nil
}

// GetSessionIDFromAccessToken parses an access token and returns its session ID.
func (tm *TokenManager) GetSessionIDFromAccessToken(tokenStr string) (string, error) {
	claims, err := tm.ParseAccess(tokenStr)
	if err != nil {
		return "", err
	}

	return claims.SessionID, nil
}

// GetSessionIDFromRefreshToken parses a refresh token and returns its session ID.
func (tm *TokenManager) GetSessionIDFromRefreshToken(tokenStr string) (string, error) {
	claims, err := tm.ParseRefresh(tokenStr)
	if err != nil {
		return "", err
	}

	return claims.SessionID, nil
}
