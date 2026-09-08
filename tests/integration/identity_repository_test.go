// tests/integration/identity_api_test.go
package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// ============================================================
// TEST SETUP
// ============================================================

func TestMain(m *testing.M) {
	waitForApp()

	os.Exit(m.Run())
}

// ============================================================
// HEALTH
// ============================================================

func TestIntegration_Health(t *testing.T) {
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"Expected 200, got %d",
			resp.StatusCode,
		)
	}
}

// ============================================================
// LOGIN
// ============================================================

func TestIntegration_Login_WithUsername(t *testing.T) {
	user, _ := createTestUser(t)

	auth := loginUser(
		t,
		user.Username,
		user.Password,
	)

	if auth.AccessToken == "" {
		t.Fatal("Expected access token, got empty string")
	}

	if auth.RefreshToken == "" {
		t.Fatal("Expected refresh token, got empty string")
	}

	if int(auth.UserID) != int(user.UserID) {
		t.Fatalf(
			"Expected user ID %d, got %d",
			int(user.UserID),
			int(auth.UserID),
		)
	}

	if auth.Message != "login successful" {
		t.Fatalf(
			"Expected login successful message, got %q",
			auth.Message,
		)
	}
}

func TestIntegration_Login_WithEmail(t *testing.T) {
	user, _ := createTestUser(t)

	auth := loginUser(
		t,
		user.Email,
		user.Password,
	)

	if auth.AccessToken == "" {
		t.Fatal("Expected access token, got empty string")
	}

	if auth.RefreshToken == "" {
		t.Fatal("Expected refresh token, got empty string")
	}

	if int(auth.UserID) != int(user.UserID) {
		t.Fatalf(
			"Expected user ID %d, got %d",
			int(user.UserID),
			int(auth.UserID),
		)
	}
}

func TestIntegration_Login_InvalidPassword(t *testing.T) {
	user, _ := createTestUser(t)

	status, body := doRequest(
		t,
		http.MethodPost,
		"/login",
		"",
		map[string]string{
			"usernameoremail": user.Username,
			"password":        "WrongPassword123!",
		},
	)

	if status != http.StatusUnauthorized {
		t.Fatalf(
			"Expected 401, got %d: %s",
			status,
			string(body),
		)
	}
}

func TestIntegration_Login_NonexistentUser(t *testing.T) {
	status, body := doRequest(
		t,
		http.MethodPost,
		"/login",
		"",
		map[string]string{
			"usernameoremail": "does_not_exist_123456",
			"password":        "SecurePass123!",
		},
	)

	if status != http.StatusNotFound {
		t.Fatalf(
			"Expected 404, got %d: %s",
			status,
			string(body),
		)
	}
}

func TestIntegration_Login_InvalidRequest(t *testing.T) {
	status, body := doRequest(
		t,
		http.MethodPost,
		"/login",
		"",
		map[string]string{
			"usernameoremail": "",
			"password":        "",
		},
	)

	if status != http.StatusBadRequest {
		t.Fatalf(
			"Expected 400, got %d: %s",
			status,
			string(body),
		)
	}
}

// ============================================================
// REFRESH LOGIN
// ============================================================

func TestIntegration_RefreshLogin(t *testing.T) {
	user, auth := createTestUser(t)

	status, body := doRequestWithRefresh(
		t,
		http.MethodPost,
		"/refresh",
		auth.RefreshToken,
		map[string]string{},
	)

	if status != http.StatusOK {
		t.Fatalf(
			"Expected 200, got %d: %s",
			status,
			string(body),
		)
	}

	var refreshed AuthResponse

	if err := json.Unmarshal(body, &refreshed); err != nil {
		t.Fatalf(
			"Failed to decode refresh response: %v",
			err,
		)
	}

	if refreshed.AccessToken == "" {
		t.Fatal("Expected new access token")
	}

	if refreshed.RefreshToken == "" {
		t.Fatal("Expected new refresh token")
	}

	if int(refreshed.UserID) != int(user.UserID) {
		t.Fatalf(
			"Expected user ID %d, got %d",
			int(user.UserID),
			int(refreshed.UserID),
		)
	}

	if refreshed.AccessToken == auth.AccessToken {
		t.Fatal("Expected refreshed access token to be different")
	}

	if refreshed.RefreshToken == auth.RefreshToken {
		t.Fatal("Expected refreshed refresh token to be different")
	}
}

func TestIntegration_RefreshLogin_RotatesRefreshToken(t *testing.T) {
	_, auth := createTestUser(t)

	status, body := doRequestWithRefresh(
		t,
		http.MethodPost,
		"/refresh",
		auth.RefreshToken,
		map[string]string{},
	)

	if status != http.StatusOK {
		t.Fatalf(
			"Expected 200, got %d: %s",
			status,
			string(body),
		)
	}

	var refreshed AuthResponse

	if err := json.Unmarshal(body, &refreshed); err != nil {
		t.Fatalf(
			"Failed to decode response: %v",
			err,
		)
	}

	// The new refresh token should not be the old one.
	if refreshed.RefreshToken == auth.RefreshToken {
		t.Fatal("Refresh token was not rotated")
	}

	// If your implementation rotates/revokes old refresh tokens,
	// the old refresh token must no longer work.
	status, body = doRequest(
		t,
		http.MethodPost,
		"/refresh",
		"",
		map[string]string{
			"refresh_token": auth.RefreshToken,
		},
	)

	if status != http.StatusUnauthorized {
		t.Fatalf(
			"Expected old refresh token to return 401, got %d: %s",
			status,
			string(body),
		)
	}
}

func TestIntegration_RefreshLogin_MissingToken(t *testing.T) {
	status, body := doRequestWithRefresh(
		t,
		http.MethodPost,
		"/refresh",
		"",
		map[string]string{},
	)

	if status != http.StatusUnauthorized {
		t.Fatalf(
			"Expected 401, got %d: %s",
			status,
			string(body),
		)
	}
}

func TestIntegration_RefreshLogin_InvalidToken(t *testing.T) {
	status, body := doRequest(
		t,
		http.MethodPost,
		"/refresh",
		"this-is-not-a-valid-refresh-token",
		map[string]string{},
	)

	if status != http.StatusUnauthorized {
		t.Fatalf(
			"Expected 401, got %d: %s",
			status,
			string(body),
		)
	}
}

// ============================================================
// LOGOUT USER
// ============================================================

func TestIntegration_Logout(t *testing.T) {
	user, auth := createTestUser(t)

	// Logout the current session.
	status, body := doRequest(
		t,
		http.MethodPost,
		"/logout",
		auth.AccessToken,
		nil,
	)

	if status != http.StatusOK {
		t.Fatalf(
			"Expected 200, got %d: %s",
			status,
			string(body),
		)
	}

	// The session should now be revoked.
	//
	// Try to refresh using the refresh token belonging
	// to the logged-out session.
	status, body = doRequest(
		t,
		http.MethodPost,
		"/refresh",
		"",
		map[string]string{
			"refresh_token": auth.RefreshToken,
		},
	)

	if status != http.StatusUnauthorized {
		t.Fatalf(
			"Expected 401 when refreshing after logout, got %d: %s",
			status,
			string(body),
		)
	}

	// Make sure the user itself still exists.
	stored := getUserByID(
		t,
		int(user.UserID),
		// We cannot use the logged-out access token for this
		// request, so login through another session.
		loginUser(t, user.Username, user.Password).AccessToken,
	)

	if stored.ID != int32(user.UserID) {
		t.Fatalf(
			"Expected user ID %f, got %d",
			user.UserID,
			stored.ID,
		)
	}
}

func TestIntegration_Logout_DoesNotDeleteUser(t *testing.T) {
	user, auth := createTestUser(t)

	status, body := doRequest(
		t,
		http.MethodPost,
		"/logout",
		auth.AccessToken,
		nil,
	)

	if status != http.StatusOK {
		t.Fatalf(
			"Expected 200, got %d: %s",
			status,
			string(body),
		)
	}

	// Logout should only revoke the session.
	// The user should still be able to login.
	newAuth := loginUser(
		t,
		user.Username,
		user.Password,
	)

	if newAuth.AccessToken == "" {
		t.Fatal("Expected new access token after logging in again")
	}

	if newAuth.RefreshToken == "" {
		t.Fatal("Expected new refresh token after logging in again")
	}
}

func TestIntegration_Logout_InvalidToken(t *testing.T) {
	status, body := doRequest(
		t,
		http.MethodPost,
		"/logout",
		"invalid-access-token",
		nil,
	)

	if status != http.StatusUnauthorized &&
		status != http.StatusBadRequest {
		t.Fatalf(
			"Expected 401 or 400, got %d: %s",
			status,
			string(body),
		)
	}
}

// ============================================================
// LOGOUT ALL
// ============================================================

func TestIntegration_LogoutAll(t *testing.T) {
	user, auth1 := createTestUser(t)

	// Create a second independent session for the same user.
	auth2 := loginUser(
		t,
		user.Username,
		user.Password,
	)

	if auth1.AccessToken == auth2.AccessToken {
		t.Fatal("Expected separate login sessions to have different access tokens")
	}

	if auth1.RefreshToken == auth2.RefreshToken {
		t.Fatal("Expected separate login sessions to have different refresh tokens")
	}

	// Logout all sessions using the first access token.
	status, body := doRequest(
		t,
		http.MethodPost,
		"/logout/all",
		auth1.AccessToken,
		nil,
	)

	if status != http.StatusOK {
		t.Fatalf(
			"Expected 200, got %d: %s",
			status,
			string(body),
		)
	}

	// First session should be revoked.
	status, body = doRequest(
		t,
		http.MethodPost,
		"/refresh",
		"",
		map[string]string{
			"refresh_token": auth1.RefreshToken,
		},
	)

	if status != http.StatusUnauthorized {
		t.Fatalf(
			"Expected first session refresh to return 401, got %d: %s",
			status,
			string(body),
		)
	}

	// Second session should ALSO be revoked.
	status, body = doRequest(
		t,
		http.MethodPost,
		"/refresh",
		"",
		map[string]string{
			"refresh_token": auth2.RefreshToken,
		},
	)

	if status != http.StatusUnauthorized {
		t.Fatalf(
			"Expected second session refresh to return 401, got %d: %s",
			status,
			string(body),
		)
	}

	// The user itself should still exist and be able to log in again.
	newAuth := loginUser(
		t,
		user.Username,
		user.Password,
	)

	if newAuth.AccessToken == "" {
		t.Fatal("Expected user to be able to login after LogoutAll")
	}
}

func TestIntegration_LogoutAll_RequiresAuthentication(t *testing.T) {
	status, body := doRequest(
		t,
		http.MethodPost,
		"/logout/all",
		"",
		nil,
	)

	if status != http.StatusUnauthorized {
		t.Fatalf(
			"Expected 401, got %d: %s",
			status,
			string(body),
		)
	}
}

// ============================================================
// CREATE USER
// ============================================================

func TestIntegration_Register_PersistsUser(t *testing.T) {
	user, auth := createTestUser(t)

	stored := getUserByID(
		t,
		int(user.UserID),
		auth.AccessToken,
	)

	if stored.ID != int32(user.UserID) {
		t.Errorf(
			"Expected ID %f, got %d",
			user.UserID,
			stored.ID,
		)
	}

	if stored.Username != user.Username {
		t.Errorf(
			"Expected username %q, got %q",
			user.Username,
			stored.Username,
		)
	}

	if stored.Email != user.Email {
		t.Errorf(
			"Expected email %q, got %q",
			user.Email,
			stored.Email,
		)
	}
}

func TestIntegration_Register_DuplicateUsername(t *testing.T) {
	user, _ := createTestUser(t)

	input := map[string]string{
		"username":  user.Username,
		"email":     fmt.Sprintf("different%d@test.com", time.Now().UnixNano()),
		"password":  "AnotherPass123!",
		"birthdate": "1990-01-01",
	}

	status, body := doRequest(
		t,
		http.MethodPost,
		"/register",
		"",
		input,
	)

	if status != http.StatusConflict {
		t.Fatalf(
			"Expected 409, got %d: %s",
			status,
			string(body),
		)
	}
}

func TestIntegration_Register_DuplicateEmail(t *testing.T) {
	user, _ := createTestUser(t)

	input := map[string]string{
		"username":  fmt.Sprintf("different_%d", time.Now().UnixNano()),
		"email":     user.Email,
		"password":  "AnotherPass123!",
		"birthdate": "1990-01-01",
	}

	status, body := doRequest(
		t,
		http.MethodPost,
		"/register",
		"",
		input,
	)

	if status != http.StatusConflict {
		t.Fatalf(
			"Expected 409, got %d: %s",
			status,
			string(body),
		)
	}
}

// ============================================================
// GET USER BY ID
// ============================================================

func TestIntegration_GetUserByID(t *testing.T) {
	user, auth := createTestUser(t)

	stored := getUserByID(
		t,
		int(user.UserID),
		auth.AccessToken,
	)

	if stored.ID != int32(user.UserID) {
		t.Errorf(
			"Expected ID %f, got %d",
			user.UserID,
			stored.ID,
		)
	}
}

func TestIntegration_GetUserByID_NotFound(t *testing.T) {
	_, auth := createTestUser(t)

	status, body := doRequest(
		t,
		http.MethodGet,
		"/user/999999999",
		auth.AccessToken,
		nil,
	)

	if status != http.StatusNotFound {
		t.Fatalf(
			"Expected 404, got %d: %s",
			status,
			string(body),
		)
	}
}

// ============================================================
// GET USER BY EMAIL
// ============================================================

func TestIntegration_GetUserByEmail(t *testing.T) {
	user, auth := createTestUser(t)

	status, body := doRequest(
		t,
		http.MethodGet,
		"/user/email/"+user.Email,
		auth.AccessToken,
		nil,
	)

	if status != http.StatusOK && status != http.StatusFound {
		t.Fatalf(
			"Expected 200/302, got %d: %s",
			status,
			string(body),
		)
	}

	var stored UserResponse

	if err := json.Unmarshal(body, &stored); err != nil {
		t.Fatalf(
			"Failed to decode response: %v",
			err,
		)
	}

	if stored.ID != int32(user.UserID) {
		t.Errorf(
			"Expected ID %f, got %d",
			user.UserID,
			stored.ID,
		)
	}

	if stored.Email != user.Email {
		t.Errorf(
			"Expected email %q, got %q",
			user.Email,
			stored.Email,
		)
	}
}

func TestIntegration_GetUserByEmail_NotFound(t *testing.T) {
	_, auth := createTestUser(t)

	status, body := doRequest(
		t,
		http.MethodGet,
		"/user/email/nonexistent_"+fmt.Sprintf("%d", time.Now().UnixNano())+"@test.com",
		auth.AccessToken,
		nil,
	)

	if status != http.StatusNotFound {
		t.Fatalf(
			"Expected 404, got %d: %s",
			status,
			string(body),
		)
	}
}

// ============================================================
// GET USER BY USERNAME
// ============================================================

func TestIntegration_GetUserByUsername(t *testing.T) {
	user, auth := createTestUser(t)

	status, body := doRequest(
		t,
		http.MethodGet,
		"/user/name/"+user.Username,
		auth.AccessToken,
		nil,
	)

	if status != http.StatusOK && status != http.StatusFound {
		t.Fatalf(
			"Expected 200/302, got %d: %s",
			status,
			string(body),
		)
	}

	var stored UserResponse

	if err := json.Unmarshal(body, &stored); err != nil {
		t.Fatalf(
			"Failed to decode response: %v",
			err,
		)
	}

	if stored.ID != int32(user.UserID) {
		t.Errorf(
			"Expected ID %f, got %d",
			user.UserID,
			stored.ID,
		)
	}

	if stored.Username != user.Username {
		t.Errorf(
			"Expected username %q, got %q",
			user.Username,
			stored.Username,
		)
	}
}

func TestIntegration_GetUserByUsername_NotFound(t *testing.T) {
	_, auth := createTestUser(t)

	username := fmt.Sprintf(
		"nonexistent_%d",
		time.Now().UnixNano(),
	)

	status, body := doRequest(
		t,
		http.MethodGet,
		"/user/username/"+username,
		auth.AccessToken,
		nil,
	)

	if status != http.StatusNotFound {
		t.Fatalf(
			"Expected 404, got %d: %s",
			status,
			string(body),
		)
	}
}

// ============================================================
// UPDATE USER
// ============================================================

func TestIntegration_UpdateUser_PersistsChanges(t *testing.T) {
	user, auth := createTestUser(t)

	newUsername := fmt.Sprintf(
		"updated_%d",
		time.Now().UnixNano(),
	)

	newEmail := fmt.Sprintf(
		"updated%d@test.com",
		time.Now().UnixNano(),
	)

	input := map[string]string{
		"username":  newUsername,
		"email":     newEmail,
		"birthdate": "2000-10-20",
	}

	status, body := doRequest(
		t,
		http.MethodPut,
		"/user",
		auth.AccessToken,
		input,
	)

	if status != http.StatusOK {
		t.Fatalf(
			"Expected 200, got %d: %s",
			status,
			string(body),
		)
	}

	// Read directly through the API again.
	// This verifies that UpdateUser persisted the changes.
	stored := getUserByID(
		t,
		int(user.UserID),
		auth.AccessToken,
	)

	if stored.Username != newUsername {
		t.Errorf(
			"Expected username %q, got %q",
			newUsername,
			stored.Username,
		)
	}

	if stored.Email != newEmail {
		t.Errorf(
			"Expected email %q, got %q",
			newEmail,
			stored.Email,
		)
	}
}

func TestIntegration_UpdateUser_DuplicateUsername(t *testing.T) {
	userA, _ := createTestUser(t)
	userB, authB := createTestUser(t)

	input := map[string]string{
		"username":  userA.Username,
		"email":     userB.Email,
		"birthdate": userB.Birthdate,
	}

	status, body := doRequest(
		t,
		http.MethodPut,
		"/user",
		authB.AccessToken,
		input,
	)

	if status != http.StatusConflict {
		t.Fatalf(
			"Expected 409, got %d: %s",
			status,
			string(body),
		)
	}
}

func TestIntegration_UpdateUser_DuplicateEmail(t *testing.T) {
	userA, _ := createTestUser(t)
	userB, authB := createTestUser(t)

	input := map[string]string{
		"username":  userB.Username,
		"email":     userA.Email,
		"birthdate": userB.Birthdate,
	}

	status, body := doRequest(
		t,
		http.MethodPut,
		"/user",
		authB.AccessToken,
		input,
	)

	if status != http.StatusConflict {
		t.Fatalf(
			"Expected 409, got %d: %s",
			status,
			string(body),
		)
	}
}

// ============================================================
// CHANGE PASSWORD
// ============================================================

func TestIntegration_ChangePassword_PersistsChange(t *testing.T) {
	user, auth := createTestUser(t)

	newPassword := "NewSecurePass456!"

	input := map[string]string{
		"current_password": user.Password,
		"new_password":     newPassword,
	}

	status, body := doRequest(
		t,
		http.MethodPatch,
		"/user/password/"+fmt.Sprintf("%d", int(user.UserID)),
		auth.AccessToken,
		input,
	)

	if status != http.StatusOK {
		t.Fatalf(
			"Expected 200, got %d: %s",
			status,
			string(body),
		)
	}

	// Old password should no longer authenticate.
	oldStatus, _ := doRequest(
		t,
		http.MethodPost,
		"/login",
		"",
		map[string]string{
			"username": user.Username,
			"password": user.Password,
		},
	)

	if oldStatus == http.StatusOK {
		t.Fatal("Old password still works after password change")
	}

	// New password must authenticate.
	newAuth := loginUser(
		t,
		user.Username,
		newPassword,
	)

	if newAuth.AccessToken == "" {
		t.Fatal("Expected access token with new password")
	}

	if newAuth.RefreshToken == "" {
		t.Fatal("Expected refresh token with new password")
	}
}

// ============================================================
// DELETE USER
// ============================================================

func TestIntegration_DeleteUser_RemovesUser(t *testing.T) {
	user, auth := createTestUser(t)

	status, body := doRequest(
		t,
		http.MethodDelete,
		fmt.Sprintf("/user/id/%d", int(user.UserID)),
		auth.AccessToken,
		nil,
	)

	if status != http.StatusOK {
		t.Fatalf(
			"Expected 200, got %d: %s",
			status,
			string(body),
		)
	}

	// Verify database record is gone.
	status, body = doRequest(
		t,
		http.MethodGet,
		fmt.Sprintf("/user/%f", user.UserID),
		auth.AccessToken,
		nil,
	)

	if status != http.StatusNotFound {
		t.Fatalf(
			"Expected 404 after deletion, got %d: %s",
			status,
			string(body),
		)
	}
}

func TestIntegration_DeleteUser_PreventsLogin(t *testing.T) {
	user, auth := createTestUser(t)

	status, body := doRequest(
		t,
		http.MethodDelete,
		fmt.Sprintf("/user/id/%d", int(user.UserID)),
		auth.AccessToken,
		nil,
	)

	if status != http.StatusOK {
		t.Fatalf(
			"Expected 200, got %d: %s",
			status,
			string(body),
		)
	}

	// User should no longer exist in the database,
	// therefore authentication should fail.
	status, _ = doRequest(
		t,
		http.MethodPost,
		"/login",
		"",
		map[string]string{
			"username": user.Username,
			"password": user.Password,
		},
	)

	if status == http.StatusOK {
		t.Fatal("Deleted user can still log in")
	}
}

// ============================================================
// DATABASE PERSISTENCE ACROSS REQUESTS
// ============================================================

func TestIntegration_UserPersistsAcrossRequests(t *testing.T) {
	user, auth := createTestUser(t)

	// First request retrieves the user.
	first := getUserByID(
		t,
		int(user.UserID),
		auth.AccessToken,
	)

	// Second independent request retrieves the same user.
	second := getUserByID(
		t,
		int(user.UserID),
		auth.AccessToken,
	)

	if first.ID != second.ID {
		t.Fatalf(
			"User ID changed between requests: %d != %d",
			first.ID,
			second.ID,
		)
	}

	if first.Username != second.Username {
		t.Fatalf(
			"Username changed between requests: %q != %q",
			first.Username,
			second.Username,
		)
	}

	if first.Email != second.Email {
		t.Fatalf(
			"Email changed between requests: %q != %q",
			first.Email,
			second.Email,
		)
	}
}
