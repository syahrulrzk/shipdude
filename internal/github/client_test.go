package github

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExchangeCodeForToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock token exchange
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "gho_mock_access_token_123456",
			Scope:       "repo",
			TokenType:   "bearer",
		})
	}))
	defer server.Close()

	// Override OAuth URL
	oldOAuthURL := OAuthURL
	OAuthURL = server.URL
	defer func() { OAuthURL = oldOAuthURL }()

	token, err := ExchangeCodeForToken("client_id_val", "client_secret_val", "auth_code_val", "redirect_val")
	if err != nil {
		t.Fatalf("unexpected error in ExchangeCodeForToken: %v", err)
	}

	if token != "gho_mock_access_token_123456" {
		t.Errorf("expected 'gho_mock_access_token_123456', got '%s'", token)
	}
}

func TestListUserRepositories(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		repos := []Repository{
			{
				FullName:      "user4xn/my-public-repo",
				HTMLURL:       "https://github.com/user4xn/my-public-repo",
				DefaultBranch: "main",
			},
			{
				FullName:      "user4xn/my-admin-repo",
				HTMLURL:       "https://github.com/user4xn/my-admin-repo",
				DefaultBranch: "development",
			},
		}
		// Grant admin permission to only the second repo
		repos[1].Permissions.Admin = true

		json.NewEncoder(w).Encode(repos)
	}))
	defer server.Close()

	// Override Base API URL
	oldBaseURL := BaseURL
	BaseURL = server.URL
	defer func() { BaseURL = oldBaseURL }()

	repos, err := ListUserRepositories("mock_token")
	if err != nil {
		t.Fatalf("unexpected error listing repos: %v", err)
	}

	// Should filter and return only the repository where user has admin/push permissions
	if len(repos) != 1 {
		t.Fatalf("expected 1 repository, got %d", len(repos))
	}

	if repos[0].FullName != "user4xn/my-admin-repo" {
		t.Errorf("expected 'user4xn/my-admin-repo', got '%s'", repos[0].FullName)
	}
	if repos[0].DefaultBranch != "development" {
		t.Errorf("expected branch 'development', got '%s'", repos[0].DefaultBranch)
	}
}

func TestGetRepoPublicKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PublicKeyResponse{
			KeyID: "key_id_112233",
			Key:   base64.StdEncoding.EncodeToString(make([]byte, 32)), // 32-byte key
		})
	}))
	defer server.Close()

	oldBaseURL := BaseURL
	BaseURL = server.URL
	defer func() { BaseURL = oldBaseURL }()

	keyID, _, err := GetRepoPublicKey("mock_token", "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error getting public key: %v", err)
	}

	if keyID != "key_id_112233" {
		t.Errorf("expected 'key_id_112233', got '%s'", keyID)
	}
}

func TestCommitWorkflowFile(t *testing.T) {
	var receivedPUTBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// Mock check workflow file, return 404 (does not exist yet)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if r.Method == "PUT" {
			w.Header().Set("Content-Type", "application/json")
			json.NewDecoder(r.Body).Decode(&receivedPUTBody)
			w.WriteHeader(http.StatusCreated)
			return
		}
	}))
	defer server.Close()

	oldBaseURL := BaseURL
	BaseURL = server.URL
	defer func() { BaseURL = oldBaseURL }()

	err := CommitWorkflowFile("mock_token", "owner", "repo", "main", "yaml-content-string")
	if err != nil {
		t.Fatalf("unexpected error committing workflow: %v", err)
	}

	if receivedPUTBody == nil {
		t.Fatalf("expected PUT request body to be received")
	}

	msg := receivedPUTBody["message"].(string)
	if msg != "ci: inject ShipDude auto deployment workflow" {
		t.Errorf("expected custom message, got '%s'", msg)
	}

	b64Val := receivedPUTBody["content"].(string)
	decodedBytes, _ := base64.StdEncoding.DecodeString(b64Val)
	if string(decodedBytes) != "yaml-content-string" {
		t.Errorf("expected workflow content 'yaml-content-string', got '%s'", string(decodedBytes))
	}
}
