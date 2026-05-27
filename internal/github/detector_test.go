package github

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectStack_Go(t *testing.T) {
	// 1. Create Mock Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock root contents list
		if r.URL.Path == "/repos/username/go-app/contents" {
			files := []GitHubFile{
				{Name: "go.mod", Type: "file", Size: 100},
				{Name: "main.go", Type: "file", Size: 200},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(files)
			return
		}

		// Mock go.mod contents
		if r.URL.Path == "/repos/username/go-app/contents/go.mod" {
			rawContent := "module go-app\n\ngo 1.25\n"
			encodedContent := base64.StdEncoding.EncodeToString([]byte(rawContent))
			file := GitHubFile{
				Name:    "go.mod",
				Type:    "file",
				Size:    100,
				Content: encodedContent,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(file)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// 2. Override BaseURL to point to our mock server
	oldBaseURL := BaseURL
	BaseURL = server.URL
	defer func() { BaseURL = oldBaseURL }()

	// 3. Run Detection
	info, err := DetectStack("username/go-app", "")
	if err != nil {
		t.Fatalf("Unexpected error in DetectStack: %v", err)
	}

	// 4. Assertions
	if info.Language != "go" {
		t.Errorf("Expected language 'go', got '%s'", info.Language)
	}
	if info.Version != "1.25-alpine" {
		t.Errorf("Expected version '1.25-alpine', got '%s'", info.Version)
	}
	if info.DefaultPort != 8080 {
		t.Errorf("Expected default port 8080, got %d", info.DefaultPort)
	}
	if len(info.DetectedFiles) != 1 || info.DetectedFiles[0] != "go.mod" {
		t.Errorf("Expected detected files ['go.mod'], got %v", info.DetectedFiles)
	}
}

func TestDetectStack_Node(t *testing.T) {
	// 1. Create Mock Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock root contents list
		if r.URL.Path == "/repos/username/node-app/contents" {
			files := []GitHubFile{
				{Name: "package.json", Type: "file", Size: 100},
				{Name: "index.js", Type: "file", Size: 200},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(files)
			return
		}

		// Mock package.json contents
		if r.URL.Path == "/repos/username/node-app/contents/package.json" {
			rawContent := `{"name": "node-app", "engines": {"node": ">=18.0.0"}}`
			encodedContent := base64.StdEncoding.EncodeToString([]byte(rawContent))
			file := GitHubFile{
				Name:    "package.json",
				Type:    "file",
				Size:    100,
				Content: encodedContent,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(file)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// 2. Override BaseURL
	oldBaseURL := BaseURL
	BaseURL = server.URL
	defer func() { BaseURL = oldBaseURL }()

	// 3. Run Detection
	info, err := DetectStack("username/node-app", "")
	if err != nil {
		t.Fatalf("Unexpected error in DetectStack: %v", err)
	}

	// 4. Assertions
	if info.Language != "node" {
		t.Errorf("Expected language 'node', got '%s'", info.Language)
	}
	if info.Version != "18-alpine" {
		t.Errorf("Expected version '18-alpine', got '%s'", info.Version)
	}
	if info.DefaultPort != 3000 {
		t.Errorf("Expected default port 3000, got %d", info.DefaultPort)
	}
}

func TestDetectStack_WithDockerfileExpose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/username/exposed-app/contents" {
			files := []GitHubFile{
				{Name: "package.json", Type: "file", Size: 100},
				{Name: "Dockerfile", Type: "file", Size: 150},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(files)
			return
		}

		if r.URL.Path == "/repos/username/exposed-app/contents/package.json" {
			rawContent := `{"name": "exposed-app"}`
			encodedContent := base64.StdEncoding.EncodeToString([]byte(rawContent))
			file := GitHubFile{Name: "package.json", Type: "file", Size: 100, Content: encodedContent}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(file)
			return
		}

		if r.URL.Path == "/repos/username/exposed-app/contents/Dockerfile" {
			rawContent := "FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nEXPOSE 5000\nCMD [\"node\", \"index.js\"]\n"
			encodedContent := base64.StdEncoding.EncodeToString([]byte(rawContent))
			file := GitHubFile{Name: "Dockerfile", Type: "file", Size: 150, Content: encodedContent}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(file)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	oldBaseURL := BaseURL
	BaseURL = server.URL
	defer func() { BaseURL = oldBaseURL }()

	info, err := DetectStack("username/exposed-app", "")
	if err != nil {
		t.Fatalf("Unexpected error in DetectStack: %v", err)
	}

	if !info.HasDockerfile {
		t.Errorf("Expected HasDockerfile to be true")
	}
	if info.DefaultPort != 5000 {
		t.Errorf("Expected default port to be 5000 (from EXPOSE), got %d", info.DefaultPort)
	}
}
