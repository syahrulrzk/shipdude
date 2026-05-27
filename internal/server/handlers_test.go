package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"shipdude/internal/db"
	"shipdude/internal/github"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/ssh"
)

// Helper to generate temporary host key for mock SSH
func generateTestHostKey(t *testing.T) ssh.Signer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test RSA key: %v", err)
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	signer, err := ssh.ParsePrivateKey(pem.EncodeToMemory(privateKeyPEM))
	if err != nil {
		t.Fatalf("Failed to parse private test key: %v", err)
	}

	return signer
}

// Helper to spawn a mock SSH server
func startMockSSHServer(t *testing.T, hostKey ssh.Signer, user string, password string) (string, io.Closer) {
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if conn.User() == user && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("auth failed")
		},
	}
	config.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	go func() {
		for {
			nConn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				_, chans, reqs, err := ssh.NewServerConn(c, config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)

				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}

					channel, requests, err := newChan.Accept()
					if err != nil {
						return
					}

					go func(in <-chan *ssh.Request, ch ssh.Channel) {
						defer ch.Close()
						for req := range in {
							switch req.Type {
							case "exec":
								cmd := string(req.Payload[4 : 4+req.Payload[3]])
								if strings.Contains(cmd, "authorized_keys") {
									ch.Write([]byte("key injected successfully"))
								} else if strings.Contains(cmd, "cat /etc/os-release") {
									ch.Write([]byte("PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n"))
								} else if strings.Contains(cmd, "docker --version") {
									ch.Write([]byte("Docker version 25.0.3\n"))
								} else if strings.Contains(cmd, "docker compose version") {
									ch.Write([]byte("Docker Compose version v2.24.5\n"))
								} else if strings.Contains(cmd, "groups") {
									ch.Write([]byte("deployer docker admin\n"))
								} else if strings.Contains(cmd, "id -u deployer") {
									ch.Write([]byte("1001\n"))
								} else if strings.Contains(cmd, "docker ps -a --filter 'name=shipdude-caddy'") {
									ch.Write([]byte("shipdude-caddy\n"))
								} else if strings.Contains(cmd, "sudo -n true") {
									// exit status 0 (no response body needed)
								}
								req.Reply(true, nil)

								status := make([]byte, 4) // exit status 0
								ch.SendRequest("exit-status", false, status)
								return
							default:
								req.Reply(false, nil)
							}
						}
					}(requests, channel)
				}
			}(nConn)
		}
	}()

	return listener.Addr().String(), listener
}

func TestSettingsHandler(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "shipdude-server-test")
	defer os.RemoveAll(tmpDir)
	store, _ := db.NewStore(filepath.Join(tmpDir, "shipdude.db"))
	defer store.Close()

	ctx := NewServerContext(store)

	// Verify unconfigured settings initially
	req := httptest.NewRequest("GET", "/api/v1/settings/github", nil)
	w := httptest.NewRecorder()
	ctx.HandleGetSettings(w, req)

	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["configured"].(bool) != false {
		t.Errorf("expected configured=false, got: %v", res["configured"])
	}

	// Post settings update
	payload := `{"client_id":"my-client-id", "client_secret":"my-client-secret"}`
	reqPost := httptest.NewRequest("POST", "/api/v1/settings/github", bytes.NewBufferString(payload))
	wPost := httptest.NewRecorder()
	ctx.HandlePostSettings(wPost, reqPost)

	if wPost.Code != http.StatusOK {
		t.Errorf("expected status 200, got: %d (body: %s)", wPost.Code, wPost.Body.String())
	}

	// Verify configured settings now
	reqVerify := httptest.NewRequest("GET", "/api/v1/settings/github", nil)
	wVerify := httptest.NewRecorder()
	ctx.HandleGetSettings(wVerify, reqVerify)

	json.Unmarshal(wVerify.Body.Bytes(), &res)
	if res["configured"].(bool) != true {
		t.Errorf("expected configured=true, got: %v", res["configured"])
	}
	if res["client_id"].(string) != "my-client-id" {
		t.Errorf("expected client_id 'my-client-id', got: '%v'", res["client_id"])
	}
}

func TestHandleGetRepos_Unauthorized(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "shipdude-server-test")
	defer os.RemoveAll(tmpDir)
	store, _ := db.NewStore(filepath.Join(tmpDir, "shipdude.db"))
	defer store.Close()

	ctx := NewServerContext(store)

	req := httptest.NewRequest("GET", "/api/v1/github/repos", nil)
	w := httptest.NewRecorder()
	ctx.HandleGetRepos(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 Unauthorized, got: %d", w.Code)
	}
}

func TestHandleDeployProject_FullFlow(t *testing.T) {
	// 1. Setup mock SSH server
	hostKey := generateTestHostKey(t)
	sshAddr, sshServer := startMockSSHServer(t, hostKey, "deployer", "mypassword")
	defer sshServer.Close()

	sshHost, sshPortStr, _ := net.SplitHostPort(sshAddr)
	var sshPort int
	fmt.Sscanf(sshPortStr, "%d", &sshPort)

	// 2. Setup mock GitHub server
	gitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "public-key") {
			// Mock public-key GET
			json.NewEncoder(w).Encode(github.PublicKeyResponse{
				KeyID: "key-123",
				Key:   base64.StdEncoding.EncodeToString(make([]byte, 32)),
			})
			return
		}
		if r.Method == "PUT" {
			// Mock secrets/workflow PUT
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == "GET" && strings.Contains(r.URL.Path, "contents") {
			if strings.Contains(r.URL.Path, "Dockerfile") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"type": "file", "name": "Dockerfile"}`))
				return
			}
			// Mock check workflow file, return 404
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}))
	defer gitServer.Close()

	// Override GitHub BaseURL
	oldBaseURL := github.BaseURL
	github.BaseURL = gitServer.URL
	defer func() { github.BaseURL = oldBaseURL }()

	// 3. Initialize SQLite store and settings
	tmpDir, _ := os.MkdirTemp("", "shipdude-server-test")
	defer os.RemoveAll(tmpDir)
	store, _ := db.NewStore(filepath.Join(tmpDir, "shipdude.db"))
	defer store.Close()

	// Preconfigure OAuth token in db settings
	store.SaveSetting("github_oauth_token", "gho_mock_token_123456")

	ctx := NewServerContext(store)

	// 4. Request deployment payload
	payload := map[string]interface{}{
		"ip_address":      sshHost,
		"ssh_port":        sshPort,
		"ssh_user":        "deployer",
		"auth_method":     "password",
		"password":        "mypassword",
		"github_repo":     "user4xn/my-website",
		"github_branch":   "main",
		"project_name":    "my-website",
		"deployment_path": "/var/www/my-website",
		"stack_type":      "go",
		"stack_version":   "1.23",
		"app_port":        8080,
	}

	bodyBytes, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/api/v1/projects/deploy", bytes.NewBuffer(bodyBytes))
	w := httptest.NewRecorder()

	ctx.HandleDeployProject(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected deployment status 200, got: %d (body: %s)", w.Code, w.Body.String())
	}

	// Wait for background job to finish
	var logs []string
	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		job := ctx.Jobs.GetJob("deploy-my-website")
		if job != nil {
			logs = job.GetLogs()
			hasSuccess := false
			hasError := false
			for _, l := range logs {
				if strings.Contains(l, "Project setup completed successfully") {
					hasSuccess = true
				}
				if strings.Contains(l, "[Error]") {
					hasError = true
				}
			}
			if hasSuccess || hasError {
				break
			}
		}
	}
	success := false
	for _, l := range logs {
		if strings.Contains(l, "Project setup completed successfully") {
			success = true
			break
		}
	}
	if !success {
		var last string
		if len(logs) > 0 {
			last = logs[len(logs)-1]
		}
		t.Fatalf("background deployment job did not finish successfully: last log: %s", last)
	}

	// 5. Verify database records
	projects, err := store.ListProjects()
	if err != nil {
		t.Fatalf("failed to list projects: %v", err)
	}
	if len(projects) != 1 {
		t.Errorf("expected 1 project created in DB, got: %d", len(projects))
	}
	if projects[0].ProjectName != "my-website" || projects[0].AppPort != 8080 {
		t.Errorf("saved project details mismatch: %+v", projects[0])
	}

	servers, err := store.ListServers()
	if err != nil {
		t.Fatalf("failed to list servers: %v", err)
	}
	if len(servers) != 1 {
		t.Errorf("expected 1 server created in DB, got: %d", len(servers))
	}
	if !strings.Contains(servers[0].SSHPrivateKey, "BEGIN RSA PRIVATE KEY") {
		t.Errorf("expected server SSH private key to be populated, got: %s", servers[0].SSHPrivateKey)
	}
}

func TestHandleStackDetect_FallbackToken(t *testing.T) {
	// 1. Setup mock GitHub server
	gitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Assert that the request contains our fallback token
		authHeader := r.Header.Get("Authorization")
		if authHeader != "token gho_mock_token_123456" && authHeader != "Bearer gho_mock_token_123456" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized key access"})
			return
		}

		// Mock contents listing (return a go.mod file structure)
		files := []github.GitHubFile{
			{Name: "go.mod", Type: "file", Size: 100},
		}
		json.NewEncoder(w).Encode(files)
	}))
	defer gitServer.Close()

	// Override GitHub BaseURL
	oldBaseURL := github.BaseURL
	github.BaseURL = gitServer.URL
	defer func() { github.BaseURL = oldBaseURL }()

	// 2. Initialize SQLite store
	tmpDir, _ := os.MkdirTemp("", "shipdude-server-test")
	defer os.RemoveAll(tmpDir)
	store, _ := db.NewStore(filepath.Join(tmpDir, "shipdude.db"))
	defer store.Close()

	// Save setting
	store.SaveSetting("github_oauth_token", "gho_mock_token_123456")

	ctx := NewServerContext(store)

	// 3. Make POST call to detect-stack without sending token in body
	payload := map[string]string{
		"repo": "user4xn/my-go-app",
	}
	bodyBytes, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/api/v1/projects/detect-stack", bytes.NewBuffer(bodyBytes))
	w := httptest.NewRecorder()

	ctx.HandleStackDetect(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got: %d (body: %s)", w.Code, w.Body.String())
	}

	var res github.StackInfo
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if res.Language != "go" {
		t.Errorf("expected language 'go', got: '%s'", res.Language)
	}
}

func TestHandleGetGitHubUser_Success(t *testing.T) {
	// Setup mock user profile endpoint
	gitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/user" {
			json.NewEncoder(w).Encode(map[string]string{
				"login":      "mock_user",
				"avatar_url": "https://example.com/avatar.png",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer gitServer.Close()

	oldBaseURL := github.BaseURL
	github.BaseURL = gitServer.URL
	defer func() { github.BaseURL = oldBaseURL }()

	tmpDir, _ := os.MkdirTemp("", "shipdude-user-test")
	defer os.RemoveAll(tmpDir)
	store, _ := db.NewStore(filepath.Join(tmpDir, "shipdude.db"))
	defer store.Close()

	store.SaveSetting("github_oauth_token", "gho_mock_user_token")

	ctx := NewServerContext(store)
	req := httptest.NewRequest("GET", "/api/v1/github/user", nil)
	w := httptest.NewRecorder()

	ctx.HandleGetGitHubUser(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var profile github.UserProfile
	if err := json.NewDecoder(w.Body).Decode(&profile); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if profile.Login != "mock_user" {
		t.Errorf("expected login 'mock_user', got '%s'", profile.Login)
	}
}

func TestHandleVPSLastConnection_Roundtrip(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "shipdude-vps-test")
	defer os.RemoveAll(tmpDir)
	store, _ := db.NewStore(filepath.Join(tmpDir, "shipdude.db"))
	defer store.Close()

	ctx := NewServerContext(store)

	// 1. Initially it should return empty values
	reqGet := httptest.NewRequest("GET", "/api/v1/vps/last-connection", nil)
	wGet := httptest.NewRecorder()
	ctx.HandleGetVPSLastConnection(wGet, reqGet)

	if wGet.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", wGet.Code)
	}

	var conn VPSLastConnection
	json.NewDecoder(wGet.Body).Decode(&conn)
	if conn.IPAddress != "" {
		t.Errorf("expected empty IP, got %s", conn.IPAddress)
	}

	// 2. Post new last connection
	newConn := VPSLastConnection{
		IPAddress:  "192.168.1.100",
		SSHPort:    2222,
		SSHUser:    "admin",
		AuthMethod: "password",
		Password:   "secret123",
	}
	bodyBytes, _ := json.Marshal(newConn)
	reqPost := httptest.NewRequest("POST", "/api/v1/vps/last-connection", bytes.NewBuffer(bodyBytes))
	wPost := httptest.NewRecorder()
	ctx.HandlePostVPSLastConnection(wPost, reqPost)

	if wPost.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", wPost.Code)
	}

	// 3. Get again and verify
	wGet2 := httptest.NewRecorder()
	ctx.HandleGetVPSLastConnection(wGet2, reqGet)

	var conn2 VPSLastConnection
	json.NewDecoder(wGet2.Body).Decode(&conn2)

	if conn2.IPAddress != "192.168.1.100" || conn2.SSHPort != 2222 || conn2.SSHUser != "admin" || conn2.Password != "secret123" {
		t.Errorf("vps connection roundtrip failed, got: %+v", conn2)
	}
}

func TestHandleGitHubDisconnect(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "shipdude-disc-test")
	defer os.RemoveAll(tmpDir)
	store, _ := db.NewStore(filepath.Join(tmpDir, "shipdude.db"))
	defer store.Close()

	store.SaveSetting("github_oauth_token", "my-awesome-token")

	ctx := NewServerContext(store)
	req := httptest.NewRequest("POST", "/api/v1/github/disconnect", nil)
	w := httptest.NewRecorder()

	ctx.HandleGitHubDisconnect(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	val, err := store.GetSetting("github_oauth_token")
	if err != nil {
		t.Fatalf("error checking setting: %v", err)
	}
	if val != "" {
		t.Errorf("expected token to be cleared, got: %s", val)
	}
}

func TestHandleGetBranches_Success(t *testing.T) {
	// Setup mock branches endpoint
	gitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/repos/mock_owner/mock_repo/branches" {
			json.NewEncoder(w).Encode([]map[string]string{
				{"name": "main"},
				{"name": "develop"},
				{"name": "feature-xyz"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer gitServer.Close()

	oldBaseURL := github.BaseURL
	github.BaseURL = gitServer.URL
	defer func() { github.BaseURL = oldBaseURL }()

	tmpDir, _ := os.MkdirTemp("", "shipdude-branches-test")
	defer os.RemoveAll(tmpDir)
	store, _ := db.NewStore(filepath.Join(tmpDir, "shipdude.db"))
	defer store.Close()

	store.SaveSetting("github_oauth_token", "gho_mock_branches_token")

	ctx := NewServerContext(store)
	req := httptest.NewRequest("GET", "/api/v1/github/branches?repo=mock_owner/mock_repo", nil)
	w := httptest.NewRecorder()

	ctx.HandleGetBranches(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var branches []github.Branch
	if err := json.NewDecoder(w.Body).Decode(&branches); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(branches) != 3 {
		t.Fatalf("expected 3 branches, got %d", len(branches))
	}

	if branches[0].Name != "main" || branches[1].Name != "develop" || branches[2].Name != "feature-xyz" {
		t.Errorf("unexpected branches payload: %+v", branches)
	}
}

func TestHandleDeployProject_ManualToken(t *testing.T) {
	// 1. Setup mock SSH server
	hostKey := generateTestHostKey(t)
	sshAddr, sshServer := startMockSSHServer(t, hostKey, "deployer", "mypassword")
	defer sshServer.Close()

	sshHost, sshPortStr, _ := net.SplitHostPort(sshAddr)
	var sshPort int
	fmt.Sscanf(sshPortStr, "%d", &sshPort)

	// 2. Setup mock GitHub server verifying that the manual token is used
	gitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "token gho_manual_token_xyz" && authHeader != "Bearer gho_manual_token_xyz" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized key access"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "public-key") {
			json.NewEncoder(w).Encode(github.PublicKeyResponse{
				KeyID: "key-manual",
				Key:   base64.StdEncoding.EncodeToString(make([]byte, 32)),
			})
			return
		}
		if r.Method == "PUT" {
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == "GET" && strings.Contains(r.URL.Path, "contents") {
			if strings.Contains(r.URL.Path, "Dockerfile") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"type": "file", "name": "Dockerfile"}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}))
	defer gitServer.Close()

	oldBaseURL := github.BaseURL
	github.BaseURL = gitServer.URL
	defer func() { github.BaseURL = oldBaseURL }()

	// 3. Initialize SQLite store (no OAuth token saved in db settings)
	tmpDir, _ := os.MkdirTemp("", "shipdude-server-manual-test")
	defer os.RemoveAll(tmpDir)
	store, _ := db.NewStore(filepath.Join(tmpDir, "shipdude.db"))
	defer store.Close()

	ctx := NewServerContext(store)

	// 4. Request deployment payload with github_token
	payload := map[string]interface{}{
		"ip_address":      sshHost,
		"ssh_port":        sshPort,
		"ssh_user":        "deployer",
		"auth_method":     "password",
		"password":        "mypassword",
		"github_repo":     "user4xn/my-website",
		"github_branch":   "main",
		"project_name":    "my-website",
		"deployment_path": "/var/www/my-website",
		"stack_type":      "go",
		"stack_version":   "1.23",
		"app_port":        8080,
		"github_token":    "gho_manual_token_xyz",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/api/v1/projects/deploy", bytes.NewReader(body))
	w := httptest.NewRecorder()

	ctx.HandleDeployProject(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got: %d (body: %s)", w.Code, w.Body.String())
	}

	// Wait for background job to finish
	var logs []string
	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		job := ctx.Jobs.GetJob("deploy-my-website")
		if job != nil {
			logs = job.GetLogs()
			hasSuccess := false
			hasError := false
			for _, l := range logs {
				if strings.Contains(l, "Project setup completed successfully") {
					hasSuccess = true
				}
				if strings.Contains(l, "[Error]") {
					hasError = true
				}
			}
			if hasSuccess || hasError {
				break
			}
		}
	}
	success := false
	for _, l := range logs {
		if strings.Contains(l, "Project setup completed successfully") {
			success = true
			break
		}
	}
	if !success {
		var last string
		if len(logs) > 0 {
			last = logs[len(logs)-1]
		}
		t.Fatalf("background deployment job did not finish successfully: last log: %s", last)
	}
}

func TestHandleListProjects(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "shipdude-list-test")
	defer os.RemoveAll(tmpDir)
	store, _ := db.NewStore(filepath.Join(tmpDir, "shipdude.db"))
	defer store.Close()

	srvID, _ := store.SaveServer(db.Server{
		Name:      "127.0.0.1",
		IPAddress: "127.0.0.1",
		SSHPort:   22,
		SSHUser:   "root",
	})
	store.SaveProject(db.Project{
		ServerID:       srvID,
		GitHubRepo:     "user4xn/my-website",
		GitHubBranch:   "main",
		ProjectName:    "my-website",
		DeploymentPath: "/var/www/my-website",
		StackType:      "go",
		StackVersion:   "1.23",
		AppPort:        8080,
		Domain:         "my-website.com",
	})
	
	ctx := NewServerContext(store)
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	w := httptest.NewRecorder()

	ctx.HandleListProjects(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var projects []db.Project
	if err := json.NewDecoder(w.Body).Decode(&projects); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}

	if projects[0].ProjectName != "my-website" || projects[0].ServerIP != "127.0.0.1" {
		t.Errorf("unexpected project details: %+v", projects[0])
	}
}

func TestHandleRollbackProject(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "shipdude-rollback-test")
	defer os.RemoveAll(tmpDir)
	store, _ := db.NewStore(filepath.Join(tmpDir, "shipdude.db"))
	defer store.Close()

	srvID, _ := store.SaveServer(db.Server{
		Name:      "127.0.0.1",
		IPAddress: "127.0.0.1",
		SSHPort:   22,
		SSHUser:   "root",
	})
	projID, _ := store.SaveProject(db.Project{
		ServerID:       srvID,
		GitHubRepo:     "user4xn/my-website",
		GitHubBranch:   "main",
		ProjectName:    "my-website",
		DeploymentPath: "/var/www/my-website",
		StackType:      "go",
		StackVersion:   "1.23",
		AppPort:        8080,
		Domain:         "my-website.com",
	})

	ctx := NewServerContext(store)
	payload := `{"target_image":"ghcr.io/user4xn/my-website:sha-abcdef"}`
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/projects/%d/rollback", projID), bytes.NewBufferString(payload))
	
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", strconv.FormatInt(projID, 10))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	ctx.HandleRollbackProject(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var res map[string]string
	json.NewDecoder(w.Body).Decode(&res)
	if res["status"] != "triggered" {
		t.Errorf("expected status 'triggered', got '%s'", res["status"])
	}
}

func TestHandleVPSProbe_Success(t *testing.T) {
	// 1. Setup mock SSH server
	hostKey := generateTestHostKey(t)
	sshAddr, sshServer := startMockSSHServer(t, hostKey, "deployer", "mypassword")
	defer sshServer.Close()

	sshHost, sshPortStr, _ := net.SplitHostPort(sshAddr)
	var sshPort int
	fmt.Sscanf(sshPortStr, "%d", &sshPort)

	// 2. Initialize SQLite store
	tmpDir, _ := os.MkdirTemp("", "shipdude-server-probe-test")
	defer os.RemoveAll(tmpDir)
	store, _ := db.NewStore(filepath.Join(tmpDir, "shipdude.db"))
	defer store.Close()

	ctx := NewServerContext(store)

	// 3. Request probe payload
	payload := map[string]interface{}{
		"ip_address":  sshHost,
		"ssh_port":    sshPort,
		"ssh_user":    "deployer",
		"auth_method": "password",
		"password":    "mypassword",
	}

	bodyBytes, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/api/v1/vps/probe", bytes.NewBuffer(bodyBytes))
	w := httptest.NewRecorder()

	ctx.HandleVPSProbe(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected probe status 200, got: %d (body: %s)", w.Code, w.Body.String())
	}

	var diags struct {
		Connected    bool `json:"connected"`
		Bootstrapped bool `json:"bootstrapped"`
	}
	if err := json.NewDecoder(w.Body).Decode(&diags); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !diags.Connected {
		t.Errorf("expected Connected=true, got false")
	}
	if !diags.Bootstrapped {
		t.Errorf("expected Bootstrapped=true, got false")
	}
}

func TestHandleDeleteProject(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "shipdude-delete-test")
	defer os.RemoveAll(tmpDir)
	store, _ := db.NewStore(filepath.Join(tmpDir, "shipdude.db"))
	defer store.Close()

	srvID, _ := store.SaveServer(db.Server{
		Name:      "127.0.0.1",
		IPAddress: "127.0.0.1",
		SSHPort:   22,
		SSHUser:   "root",
	})
	projID, _ := store.SaveProject(db.Project{
		ServerID:       srvID,
		GitHubRepo:     "user4xn/my-website",
		GitHubBranch:   "main",
		ProjectName:    "my-website",
		DeploymentPath: "/var/www/my-website",
		StackType:      "go",
		StackVersion:   "1.23",
		AppPort:        8080,
		Domain:         "my-website.com",
	})

	ctx := NewServerContext(store)
	
	r := chi.NewRouter()
	r.Delete("/api/v1/projects/{id}", ctx.HandleDeleteProject)

	req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/projects/%d", projID), nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	_, err := store.GetProject(projID)
	if err == nil {
		t.Fatal("expected project to be deleted from database, but it was found")
	}
}

