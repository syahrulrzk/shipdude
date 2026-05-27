package github

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// StackInfo represents the detected application profile
type StackInfo struct {
	Language      string   `json:"language"`
	Version       string   `json:"version"`
	DefaultPort   int      `json:"default_port"`
	DetectedFiles []string `json:"detected_files"`
	HasDockerfile bool     `json:"has_dockerfile"`
}

// GitHubFile represents a file object returned by the GitHub Contents API
type GitHubFile struct {
	Name    string `json:"name"`
	Type    string `json:"type"` // "file" or "dir"
	Size    int    `json:"size"`
	Content string `json:"content,omitempty"`
}

// BaseURL is the GitHub API base endpoint, exported for testing mocks
var BaseURL = "https://api.github.com"

// DetectStack queries the GitHub Repository contents to identify the tech stack
func DetectStack(repo string, token string) (*StackInfo, error) {
	// Parse repo path (e.g. username/repo)
	repo = strings.TrimPrefix(repo, "https://github.com/")
	repo = strings.TrimSuffix(repo, "/")

	client := &http.Client{Timeout: 10 * time.Second}

	// 1. Get repository root files
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/repos/%s/contents", BaseURL, repo), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch repo contents: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned status %d", resp.StatusCode)
	}

	var files []GitHubFile
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, err
	}

	hasPackageJSON := false
	hasGoMod := false
	hasReqs := false
	hasDockerfile := false
	var detected []string

	for _, f := range files {
		if f.Type == "file" {
			if f.Name == "Dockerfile" {
				hasDockerfile = true
				detected = append(detected, "Dockerfile")
			}
			switch f.Name {
			case "package.json":
				hasPackageJSON = true
				detected = append(detected, "package.json")
			case "go.mod":
				hasGoMod = true
				detected = append(detected, "go.mod")
			case "requirements.txt", "pyproject.toml", "Pipfile":
				hasReqs = true
				detected = append(detected, f.Name)
			}
		}
	}

	// 2. Fetch specific versions based on detected files
	if hasGoMod {
		version := "1.23-alpine" // default fallback
		content, err := fetchFileContent(client, repo, "go.mod", token)
		if err == nil {
			re := regexp.MustCompile(`(?m)^go\s+(\d+\.\d+)`)
			matches := re.FindStringSubmatch(content)
			if len(matches) > 1 {
				version = matches[1] + "-alpine"
			}
		}
		return &StackInfo{
			Language:      "go",
			Version:       version,
			DefaultPort:   8080,
			DetectedFiles: detected,
			HasDockerfile: hasDockerfile,
		}, nil
	}

	if hasPackageJSON {
		version := "20-alpine" // default fallback
		port := 3000
		content, err := fetchFileContent(client, repo, "package.json", token)
		if err == nil {
			var pkg map[string]interface{}
			if err := json.Unmarshal([]byte(content), &pkg); err == nil {
				// Try parsing node engine version
				if engines, ok := pkg["engines"].(map[string]interface{}); ok {
					if nodeVer, ok := engines["node"].(string); ok {
						// Extract major version
						re := regexp.MustCompile(`\d+`)
						major := re.FindString(nodeVer)
						if major != "" {
							version = major + "-alpine"
						}
					}
				}
			}
		}
		return &StackInfo{
			Language:      "node",
			Version:       version,
			DefaultPort:   port,
			DetectedFiles: detected,
			HasDockerfile: hasDockerfile,
		}, nil
	}

	if hasReqs {
		return &StackInfo{
			Language:      "python",
			Version:       "3.11-slim",
			DefaultPort:   8000,
			DetectedFiles: detected,
			HasDockerfile: hasDockerfile,
		}, nil
	}

	return &StackInfo{
		Language:      "unknown",
		Version:       "latest",
		DefaultPort:   80,
		DetectedFiles: detected,
		HasDockerfile: hasDockerfile,
	}, nil
}

func fetchFileContent(client *http.Client, repo string, path string, token string) (string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/repos/%s/contents/%s", BaseURL, repo, path), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	var file GitHubFile
	if err := json.NewDecoder(resp.Body).Decode(&file); err != nil {
		return "", err
	}

	// Decode base64 content
	contentRaw := strings.ReplaceAll(file.Content, "\n", "")
	contentRaw = strings.ReplaceAll(contentRaw, "\r", "")
	decoded, err := base64.StdEncoding.DecodeString(contentRaw)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}
