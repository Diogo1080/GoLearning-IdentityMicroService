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
// HELPERS
// ============================================================

func createTestUser(t *testing.T) (TestUser, AuthResponse) {
	t.Helper()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	user := TestUser{
		Username:  "db_user_" + suffix,
		Email:     "db" + suffix + "@test.com",
		Password:  "SecurePass123!",
		Birthdate: "1990-05-15",
	}

	registeredUser := registerUser(t, user)

	auth := loginUser(
		t,
		registeredUser.Username,
		registeredUser.Password,
	)

	if auth.UserID == 0 {
		t.Fatal("Expected non-zero user ID")
	}

	user.UserID = auth.UserID

	return user, auth
}

type UserResponse struct {
	ID        int32  `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Birthdate string `json:"birthdate"`
}

func getUserByID(t *testing.T, userID int, token string) UserResponse {
	t.Helper()

	status, body := doRequest(
		t,
		http.MethodGet,
		fmt.Sprintf("/user/id/%d", userID),
		token,
		nil,
	)

	if status != http.StatusOK && status != http.StatusFound {
		t.Fatalf(
			"Expected 200/302, got %d: %s",
			status,
			string(body),
		)
	}

	var user UserResponse

	if err := json.Unmarshal(body, &user); err != nil {
		t.Fatalf("Failed to decode user response: %v", err)
	}

	return user
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
