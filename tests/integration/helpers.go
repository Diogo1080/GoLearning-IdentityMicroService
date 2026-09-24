// tests/integration/helpers.go
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

var baseURL = "http://localhost:8081/api"

// TestUser holds credentials for test users (stored locally, not from API)
type TestUser struct {
	Username  string
	Email     string
	Password  string
	Birthdate string
	UserID    float64 // populated after registration
}

// RegisterResponse matches the actual register API response
type RegisterResponse struct {
	Message string  `json:"message"`
	UserID  float64 `json:"user_id"`
}

// AuthResponse matches the actual login API response
type AuthResponse struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	UserID       float64 `json:"user_id"`
	Message      string  `json:"message"`
}

type UserResponse struct {
	ID        int32  `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Birthdate string `json:"birthdate"`
}

// waitForApp waits for the application to be ready
func waitForApp() error {
	for i := 0; i < 30; i++ {
		resp, err := http.Get(baseURL + "/health")

		if err == nil {
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}

		time.Sleep(time.Second)
	}

	return fmt.Errorf(
		"application did not become ready at %s",
		baseURL,
	)
}

// registerUser registers a new user and returns the response
func registerUser(t *testing.T, user TestUser) TestUser {
	t.Helper()

	input := map[string]string{
		"username":  user.Username,
		"password":  user.Password,
		"email":     user.Email,
		"birthdate": user.Birthdate,
	}

	body, _ := json.Marshal(input)
	resp, err := http.Post(baseURL+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Register failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var regResp RegisterResponse
	json.Unmarshal(respBody, &regResp)

	// Return as AuthResponse format for consistency
	return TestUser{
		Username:  user.Username,
		Email:     user.Email,
		Password:  user.Password,
		Birthdate: user.Birthdate,
		UserID:    regResp.UserID,
	}
}

// loginUser logs in and returns the auth tokens
func loginUser(t *testing.T, identifier, password string) AuthResponse {
	t.Helper()

	input := map[string]string{
		"usernameoremail": identifier, // accepts username OR email
		"password":        password,
	}

	body, _ := json.Marshal(input)
	resp, err := http.Post(baseURL+"/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Login failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var result AuthResponse
	json.Unmarshal(respBody, &result)
	return result
}

// doRequest makes an authenticated HTTP request
func doRequest(t *testing.T, method, path, accessToken string, body interface{}) (int, []byte) {
	t.Helper()

	var reqBody io.Reader
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, baseURL+path, reqBody)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

// doRequest makes an authenticated HTTP request
func doRequestWithRefresh(t *testing.T, method, path, refreshToken string, body interface{}) (int, []byte) {
	t.Helper()

	var reqBody io.Reader
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, baseURL+path, reqBody)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if refreshToken != "" {
		req.Header.Set("X-Authorization", refreshToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

func getUserByID(t *testing.T, userID int, token string) UserResponse {
	t.Helper()

	status, body := doRequest(
		t,
		http.MethodGet,
		"/user/me",
		token,
		nil,
	)

	if status != http.StatusOK {
		t.Fatalf(
			"Expected 200, got %d: %s",
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
