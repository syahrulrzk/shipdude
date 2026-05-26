package github

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var OAuthURL = "https://github.com"

// TokenResponse represents the GitHub OAuth token exchange payload.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// Repository represents repository details returned by the GitHub API.
type Repository struct {
	FullName      string `json:"full_name"`
	HTMLURL       string `json:"html_url"`
	DefaultBranch string `json:"default_branch"`
	Permissions   struct {
		Admin bool `json:"admin"`
		Push  bool `json:"push"`
		Pull  bool `json:"pull"`
	} `json:"permissions"`
}

// PublicKeyResponse represents the repository actions secrets public key structure.
type PublicKeyResponse struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"`
}

// ExchangeCodeForToken exchanges the OAuth code for a GitHub API access token.
func ExchangeCodeForToken(clientID, clientSecret, code, redirectURI string) (string, error) {
	payload := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
		"redirect_uri":  redirectURI,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", OAuthURL+"/login/oauth/access_token", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github oauth returned status %d: %s", resp.StatusCode, string(respBytes))
	}

	var tr TokenResponse
	if err := json.Unmarshal(respBytes, &tr); err != nil {
		return "", err
	}

	if tr.Error != "" {
		return "", fmt.Errorf("oauth error: %s - %s", tr.Error, tr.ErrorDesc)
	}

	return tr.AccessToken, nil
}

// ListUserRepositories lists repositories where the user has push permissions.
func ListUserRepositories(token string) ([]Repository, error) {
	req, err := http.NewRequest("GET", BaseURL+"/user/repos?per_page=100&sort=updated", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get repos (status %d): %s", resp.StatusCode, string(body))
	}

	var repos []Repository
	if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
		return nil, err
	}

	// Filter repositories where user has admin or push (write) access
	var filtered []Repository
	for _, r := range repos {
		if r.Permissions.Admin || r.Permissions.Push {
			filtered = append(filtered, r)
		}
	}

	return filtered, nil
}

// GetRepoPublicKey retrieves the actions secrets public key for a repository.
func GetRepoPublicKey(token, owner, repo string) (string, string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/public-key", BaseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", err
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("failed to get public key (status %d): %s", resp.StatusCode, string(body))
	}

	var pk PublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&pk); err != nil {
		return "", "", err
	}

	return pk.KeyID, pk.Key, nil
}

// UploadRepoSecret uploads an encrypted actions secret to a repository.
func UploadRepoSecret(token, owner, repo, secretName, secretValue string) error {
	// 1. Get public key
	keyID, pubKeyB64, err := GetRepoPublicKey(token, owner, repo)
	if err != nil {
		return fmt.Errorf("failed to get repo public key: %w", err)
	}

	// 2. Encrypt value using sealed box
	encryptedVal, err := EncryptSecret(pubKeyB64, secretValue)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// 3. Upload secret
	url := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/%s", BaseURL, owner, repo, secretName)
	payload := map[string]string{
		"encrypted_value": encryptedVal,
		"key_id":          keyID,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to upload secret (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// CommitWorkflowFile commits the shipdude.yml deployment configuration directly.
func CommitWorkflowFile(token, owner, repo, branch, yamlContent string) error {
	path := ".github/workflows/shipdude.yml"
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s", BaseURL, owner, repo, path)

	// 1. Check if the file exists to get its current SHA (required for update PUT)
	reqCheck, err := http.NewRequest("GET", url+"?ref="+branch, nil)
	var currentSHA string
	if err == nil {
		reqCheck.Header.Set("Authorization", "token "+token)
		reqCheck.Header.Set("Accept", "application/vnd.github+json")
		client := &http.Client{}
		respCheck, errCheck := client.Do(reqCheck)
		if errCheck == nil {
			if respCheck.StatusCode == http.StatusOK {
				var info struct {
					SHA string `json:"sha"`
				}
				if json.NewDecoder(respCheck.Body).Decode(&info) == nil {
					currentSHA = info.SHA
				}
			}
			respCheck.Body.Close()
		}
	}

	// 2. Commit the content
	b64Content := base64.StdEncoding.EncodeToString([]byte(yamlContent))
	payload := map[string]interface{}{
		"message": "ci: inject ShipDude auto deployment workflow",
		"content": b64Content,
		"branch":  branch,
		"committer": map[string]string{
			"name":  "ShipDude Agent",
			"email": "agent@shipdude.dev",
		},
	}

	if currentSHA != "" {
		payload["sha"] = currentSHA
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to commit workflow file (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// ParseRepoOwner parses owner and repo name from "owner/repo" full name.
func ParseRepoOwner(fullName string) (string, string, error) {
	parts := strings.Split(fullName, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid repository format, expected 'owner/repo', got '%s'", fullName)
	}
	return parts[0], parts[1], nil
}

// UserProfile represents the GitHub user profile details.
type UserProfile struct {
	Login     string `json:"login"`
	AvatarURL string `json:"avatar_url"`
}

// GetUserProfile retrieves the authenticated user details.
func GetUserProfile(token string) (*UserProfile, error) {
	req, err := http.NewRequest("GET", BaseURL+"/user", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user profile (status %d): %s", resp.StatusCode, string(body))
	}

	var profile UserProfile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, err
	}

	return &profile, nil
}

// Branch represents a Git branch returned by the GitHub API.
type Branch struct {
	Name string `json:"name"`
}

// ListRepoBranches lists all branches in a repository.
func ListRepoBranches(token, owner, repo string) ([]Branch, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/branches?per_page=100", BaseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get branches (status %d): %s", resp.StatusCode, string(body))
	}

	var branches []Branch
	if err := json.NewDecoder(resp.Body).Decode(&branches); err != nil {
		return nil, err
	}

	return branches, nil
}
