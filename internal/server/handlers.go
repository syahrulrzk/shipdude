package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"shipdude/internal/db"
	"shipdude/internal/github"
	internalssh "shipdude/internal/ssh"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	cryptossh "golang.org/x/crypto/ssh"
)

// ServerContext aggregates store and runtime state (like OAuth states).
type ServerContext struct {
	Store  *db.Store
	states sync.Map // keeps random OAuth state parameters to prevent CSRF
	Jobs   *JobManager
}

// NewServerContext initializes a context wrapper.
func NewServerContext(store *db.Store) *ServerContext {
	return &ServerContext{
		Store: store,
		Jobs:  NewJobManager(),
	}
}

// HandleGetSettings checks if GitHub Client credentials are set.
func (ctx *ServerContext) HandleGetSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	clientID, _ := ctx.Store.GetSetting("github_client_id")
	if clientID == "" {
		clientID = os.Getenv("GITHUB_CLIENT_ID")
	}

	configured := clientID != ""
	json.NewEncoder(w).Encode(map[string]interface{}{
		"client_id":  clientID,
		"configured": configured,
	})
}

// HandlePostSettings updates the GitHub Client ID and Secret in settings.
func (ctx *ServerContext) HandlePostSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var payload struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON body"})
		return
	}

	if payload.ClientID == "" || payload.ClientSecret == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Client ID and Client Secret are required"})
		return
	}

	if err := ctx.Store.SaveSetting("github_client_id", payload.ClientID); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if err := ctx.Store.SaveSetting("github_client_secret", payload.ClientSecret); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Settings saved successfully"})
}

// HandleGitHubLogin redirects to GitHub's OAuth login portal.
func (ctx *ServerContext) HandleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	clientID, _ := ctx.Store.GetSetting("github_client_id")
	if clientID == "" {
		clientID = os.Getenv("GITHUB_CLIENT_ID")
	}

	if clientID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "GitHub Client ID is not configured"})
		return
	}

	// Generate a CSRF state token
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		http.Error(w, "Failed to generate login state", http.StatusInternalServerError)
		return
	}
	state := fmt.Sprintf("%x", stateBytes)
	ctx.states.Store(state, true)

	// Build callback redirect URL based on host domain
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	redirectURI := fmt.Sprintf("%s://%s/api/v1/auth/github/callback", scheme, r.Host)

	oauthURL := fmt.Sprintf("%s/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=repo%%20write:packages%%20read:org%%20workflow&state=%s",
		github.OAuthURL, clientID, redirectURI, state)

	http.Redirect(w, r, oauthURL, http.StatusTemporaryRedirect)
}

// HandleGitHubCallback exchanges auth code for token and redirects home.
func (ctx *ServerContext) HandleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "Missing code or state parameters", http.StatusBadRequest)
		return
	}

	// Verify CSRF state token
	if _, found := ctx.states.LoadAndDelete(state); !found {
		http.Error(w, "Invalid state token (CSRF failure)", http.StatusForbidden)
		return
	}

	clientID, _ := ctx.Store.GetSetting("github_client_id")
	if clientID == "" {
		clientID = os.Getenv("GITHUB_CLIENT_ID")
	}

	clientSecret, _ := ctx.Store.GetSetting("github_client_secret")
	if clientSecret == "" {
		clientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	redirectURI := fmt.Sprintf("%s://%s/api/v1/auth/github/callback", scheme, r.Host)

	token, err := github.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI)
	if err != nil {
		http.Error(w, "OAuth token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := ctx.Store.SaveSetting("github_oauth_token", token); err != nil {
		http.Error(w, "Failed to save OAuth token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect back to dashboard UI home
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// HandleGetRepos retrieves a list of repositories from GitHub.
func (ctx *ServerContext) HandleGetRepos(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token, _ := ctx.Store.GetSetting("github_oauth_token")
	if token == "" {
		token = os.Getenv("GITHUB_OAUTH_TOKEN")
	}

	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "GitHub OAuth login is required"})
		return
	}

	repos, err := github.ListUserRepositories(token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to retrieve repositories: " + err.Error()})
		return
	}

	json.NewEncoder(w).Encode(repos)
}

// HandleDeployProject automates key injection, secrets upload, commits, and DB storage.
func (ctx *ServerContext) HandleDeployProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		IPAddress      string `json:"ip_address"`
		SSHPort        int    `json:"ssh_port"`
		SSHUser        string `json:"ssh_user"`
		AuthMethod     string `json:"auth_method"`
		Password       string `json:"password"`
		PrivateKey     string `json:"private_key"`
		GitHubRepo     string `json:"github_repo"`
		GitHubBranch   string `json:"github_branch"`
		ProjectName    string `json:"project_name"`
		DeploymentPath string `json:"deployment_path"`
		StackType      string `json:"stack_type"`
		StackVersion   string `json:"stack_version"`
		AppPort        int    `json:"app_port"`
		GitHubToken    string `json:"github_token"`
		Domain         string `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request payload"})
		return
	}

	// Simple validation
	if req.IPAddress == "" || req.GitHubRepo == "" || req.ProjectName == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Host IP, Repository, and Project Name are required"})
		return
	}

	if req.GitHubBranch == "" {
		req.GitHubBranch = "main"
	}
	if req.SSHPort == 0 {
		req.SSHPort = 22
	}
	if req.SSHUser == "" {
		req.SSHUser = "root"
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	serverURL := scheme + "://" + r.Host

	// Save as last connection details automatically
	ctx.saveLastVPSConnection(VPSLastConnection{
		IPAddress:  req.IPAddress,
		SSHPort:    req.SSHPort,
		SSHUser:    req.SSHUser,
		AuthMethod: req.AuthMethod,
		Password:   req.Password,
		PrivateKey: req.PrivateKey,
	})

	token := req.GitHubToken
	if token == "" {
		token, _ = ctx.Store.GetSetting("github_oauth_token")
	}
	if token == "" {
		token = os.Getenv("GITHUB_OAUTH_TOKEN")
	}

	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "GitHub OAuth login required to deploy projects"})
		return
	}

	jobID := fmt.Sprintf("deploy-%s", req.ProjectName)
	job := ctx.Jobs.GetOrCreateJob(jobID)

	go func() {
		job.Mu.Lock()
		job.Logs = nil // Clear history
		job.Mu.Unlock()

		job.AddLog("[System] Starting project deployment setup...")

		job.AddLog("[System] 1. Generating SSH deployment key pair...")
		privKeyPEM, pubSSHKey, err := generateSSHKeyPair()
		if err != nil {
			job.AddLog("[Error] Failed to generate deployment keys: " + err.Error())
			return
		}

		job.AddLog("[System] 2. Injecting public key to target VPS authorized_keys...")
		probeCreds := internalssh.ProbeCredentials{
			IPAddress:  req.IPAddress,
			Port:       req.SSHPort,
			User:       req.SSHUser,
			AuthMethod: req.AuthMethod,
			Password:   req.Password,
			PrivateKey: req.PrivateKey,
		}

		err = internalssh.AddAuthorizedKey(probeCreds, pubSSHKey)
		if err != nil {
			job.AddLog("[Error] Failed to inject deployment public key: " + err.Error())
			return
		}

		job.AddLog("[System] 3. Saving server configuration to database...")
		serverID, err := ctx.Store.SaveServer(db.Server{
			Name:          req.ProjectName + "-node",
			IPAddress:     req.IPAddress,
			SSHPort:       req.SSHPort,
			SSHUser:       req.SSHUser,
			SSHPrivateKey: privKeyPEM,
		})
		if err != nil {
			job.AddLog("[Error] Failed to save server metadata: " + err.Error())
			return
		}

		job.AddLog("[GitHub] 4. Uploading SSH private key as GitHub Actions secret...")
		owner, repo, err := github.ParseRepoOwner(req.GitHubRepo)
		if err != nil {
			job.AddLog("[Error] Failed to parse repo owner: " + err.Error())
			return
		}

		err = github.UploadRepoSecret(token, owner, repo, "SHIPDUDE_SSH_PRIVATE_KEY", privKeyPEM)
		if err != nil {
			job.AddLog("[Error] Failed to configure GitHub Actions secrets: " + err.Error())
			return
		}

		job.AddLog("[GitHub] 4.5. Checking if Dockerfile exists in repository...")
		hasDockerfile, err := github.CheckFileExists(token, owner, repo, req.GitHubBranch, "Dockerfile")
		if err != nil {
			job.AddLog("[Error] Failed to verify if Dockerfile exists in repository: " + err.Error())
			return
		}

		if !hasDockerfile {
			job.AddLog("[Error] Dockerfile not found in repository root. A valid Dockerfile is required for deployment.")
			job.AddLog("[System] === REPOSITORY ELIGIBILITY REQUIREMENTS ===")
			job.AddLog("[System] 1. A valid 'Dockerfile' must exist in the root of the repository.")
			job.AddLog("[System] 2. The Dockerfile must build successfully and run a server/service.")
			job.AddLog("[System] 3. The service must listen and serve on the configured project port (e.g., PORT 3000) so that Caddy can proxy the traffic.")
			job.AddLog("[System] ============================================")
			job.AddLog("[Error] Project setup terminated due to missing requirements.")
			return
		}

		job.AddLog("[GitHub] Existing Dockerfile verified successfully!")

		job.AddLog("[GitHub] 5. Committing CI/CD workflow template to repository...")
		if strings.Contains(serverURL, "localhost") || strings.Contains(serverURL, "127.0.0.1") {
			job.AddLog("[Warning] ShipDude is running on localhost (" + serverURL + "). The target VPS will not be able to trigger hot-swap deployments automatically. Expose ShipDude via ngrok/tunnel, or run it on a public IP.")
		}
		yamlContent := generateWorkflowYAML(req.GitHubBranch, req.IPAddress, req.SSHPort, req.SSHUser, req.ProjectName, serverURL)
		err = github.CommitWorkflowFile(token, owner, repo, req.GitHubBranch, yamlContent)
		if err != nil {
			job.AddLog("[Error] Failed to commit workflow template: " + err.Error())
			return
		}

		job.AddLog("[System] 6. Persisting project metadata in database...")
		var projID int64
		existingProj, errGet := ctx.Store.GetProjectByName(req.ProjectName)
		if errGet == nil {
			err = ctx.Store.UpdateProject(db.Project{
				ID:             existingProj.ID,
				ServerID:       serverID,
				GitHubRepo:     req.GitHubRepo,
				GitHubBranch:   req.GitHubBranch,
				ProjectName:    req.ProjectName,
				DeploymentPath: req.DeploymentPath,
				StackType:      req.StackType,
				StackVersion:   req.StackVersion,
				AppPort:        req.AppPort,
				Domain:         req.Domain,
			})
			if err != nil {
				job.AddLog("[Error] Failed to update project metadata: " + err.Error())
				return
			}
			projID = existingProj.ID
			job.AddLog("[System] Existing project configuration updated in database.")
		} else {
			projID, err = ctx.Store.SaveProject(db.Project{
				ServerID:       serverID,
				GitHubRepo:     req.GitHubRepo,
				GitHubBranch:   req.GitHubBranch,
				ProjectName:    req.ProjectName,
				DeploymentPath: req.DeploymentPath,
				StackType:      req.StackType,
				StackVersion:   req.StackVersion,
				AppPort:        req.AppPort,
				Domain:         req.Domain,
			})
			if err != nil {
				job.AddLog("[Error] Failed to persist project metadata: " + err.Error())
				return
			}
			job.AddLog("[System] New project configuration created in database.")
		}

		job.AddLog(fmt.Sprintf("[System] Project setup completed successfully with Server ID: %d and Project ID: %d!", serverID, projID))
		job.AddLog("")
		job.AddLog("[Next Steps] ===============================================")
		job.AddLog("[Next Steps] 1. Go to your GitHub repository -> Actions tab.")
		job.AddLog("[Next Steps] 2. Monitor the 'ShipDude CD' workflow run.")
		job.AddLog("[Next Steps] 3. Once it finishes, it will trigger the hot-swap deploy on your VPS.")
		job.AddLog("[Next Steps] 4. Your container status will automatically update to 'Active' here!")
		job.AddLog("[Next Steps] ===============================================")
	}()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "started",
		"job_id": jobID,
	})
}

// HandleStackDetect processes stack discovery requests using optional request token or saved oauth token
func (ctx *ServerContext) HandleStackDetect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Repo  string `json:"repo"`
		Token string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request payload"})
		return
	}

	if req.Repo == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Repository URL or name is required"})
		return
	}

	// Read token from request; if empty, read from saved oauth token
	token := req.Token
	if token == "" {
		token, _ = ctx.Store.GetSetting("github_oauth_token")
	}
	if token == "" {
		token = os.Getenv("GITHUB_OAUTH_TOKEN")
	}

	info, err := github.DetectStack(req.Repo, token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(info)
}

// helper to generate key pairs in-memory
func generateSSHKeyPair() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// Encode private key to PEM
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}
	privateKeyPEM := string(pem.EncodeToMemory(privBlock))

	// Get SSH public key in authorized keys format
	publicSSHKey, err := cryptossh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicKeyStr := string(cryptossh.MarshalAuthorizedKey(publicSSHKey))

	return privateKeyPEM, publicKeyStr, nil
}

// helper to render YAML
func generateWorkflowYAML(branch, host string, port int, user, projectName, serverURL string) string {
	return fmt.Sprintf(`name: ShipDude CD
on:
  push:
    branches:
      - "%s"

permissions:
  contents: read
  packages: write

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up QEMU
        uses: docker/setup-qemu-action@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and Push Docker Image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }},ghcr.io/${{ github.repository }}:latest

      - name: Deploy to VPS via SSH
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: "%s"
          port: %d
          username: "%s"
          key: "${{ secrets.SHIPDUDE_SSH_PRIVATE_KEY }}"
          script: |
            # Trigger ShipDude agent deployment
            if command -v curl >/dev/null 2>&1; then
              curl -X POST -d '{"sha":"${{ github.sha }}"}' -H "Content-Type: application/json" "%s/api/v1/projects/deploy-trigger?repo=${{ github.repository }}"
            elif command -v wget >/dev/null 2>&1; then
              wget --post-data='{"sha":"${{ github.sha }}"}' --header='Content-Type: application/json' -O- "%s/api/v1/projects/deploy-trigger?repo=${{ github.repository }}"
            else
              echo "Error: Neither curl nor wget found on the target VPS. Cannot trigger deployment."
              exit 1
            fi
`, branch, host, port, user, serverURL, serverURL)
}

// HandleGetGitHubUser retrieves the currently authenticated GitHub user profile.
func (ctx *ServerContext) HandleGetGitHubUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token, _ := ctx.Store.GetSetting("github_oauth_token")
	if token == "" {
		token = os.Getenv("GITHUB_OAUTH_TOKEN")
	}

	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "GitHub OAuth login is required"})
		return
	}

	profile, err := github.GetUserProfile(token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(profile)
}

type VPSLastConnection struct {
	IPAddress  string `json:"ip_address"`
	SSHPort    int    `json:"ssh_port"`
	SSHUser    string `json:"ssh_user"`
	AuthMethod string `json:"auth_method"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
}

// HandleGetVPSLastConnection retrieves the saved last connection details.
func (ctx *ServerContext) HandleGetVPSLastConnection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ip, _ := ctx.Store.GetSetting("last_vps_ip")
	portStr, _ := ctx.Store.GetSetting("last_vps_port")
	user, _ := ctx.Store.GetSetting("last_vps_user")
	authMethod, _ := ctx.Store.GetSetting("last_vps_auth_method")
	password, _ := ctx.Store.GetSetting("last_vps_password")
	privateKey, _ := ctx.Store.GetSetting("last_vps_private_key")

	port := 22
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	}

	conn := VPSLastConnection{
		IPAddress:  ip,
		SSHPort:    port,
		SSHUser:    user,
		AuthMethod: authMethod,
		Password:   password,
		PrivateKey: privateKey,
	}

	json.NewEncoder(w).Encode(conn)
}

// HandlePostVPSLastConnection updates the saved last connection details manually.
func (ctx *ServerContext) HandlePostVPSLastConnection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var conn VPSLastConnection
	if err := json.NewDecoder(r.Body).Decode(&conn); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request payload"})
		return
	}

	ctx.saveLastVPSConnection(conn)

	json.NewEncoder(w).Encode(map[string]string{"message": "Last connection details updated successfully"})
}

// helper to save last connection
func (ctx *ServerContext) saveLastVPSConnection(conn VPSLastConnection) {
	ctx.Store.SaveSetting("last_vps_ip", conn.IPAddress)
	ctx.Store.SaveSetting("last_vps_port", fmt.Sprintf("%d", conn.SSHPort))
	ctx.Store.SaveSetting("last_vps_user", conn.SSHUser)
	ctx.Store.SaveSetting("last_vps_auth_method", conn.AuthMethod)
	ctx.Store.SaveSetting("last_vps_password", conn.Password)
	ctx.Store.SaveSetting("last_vps_private_key", conn.PrivateKey)
}

// HandleVPSProbe processes VPS credential diagnostics requests
func (ctx *ServerContext) HandleVPSProbe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var creds internalssh.ProbeCredentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request payload"})
		return
	}

	if creds.IPAddress == "" || creds.User == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "IP Address and SSH User are required"})
		return
	}

	// Automatically save as last connection details
	ctx.saveLastVPSConnection(VPSLastConnection{
		IPAddress:  creds.IPAddress,
		SSHPort:    creds.Port,
		SSHUser:    creds.User,
		AuthMethod: creds.AuthMethod,
		Password:   creds.Password,
		PrivateKey: creds.PrivateKey,
	})

	diags, err := internalssh.RunDiagnostics(creds)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(diags)
}

// HandleGitHubDisconnect deletes the stored GitHub OAuth token, logging the user out.
func (ctx *ServerContext) HandleGitHubDisconnect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if err := ctx.Store.SaveSetting("github_oauth_token", ""); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to disconnect: " + err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Disconnected from GitHub successfully"})
}

// HandleGetBranches retrieves the list of Git branches for the selected repository.
func (ctx *ServerContext) HandleGetBranches(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	repo := r.URL.Query().Get("repo")
	if repo == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Repository parameter 'repo' is required"})
		return
	}

	owner, repoName, err := github.ParseRepoOwner(repo)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		token, _ = ctx.Store.GetSetting("github_oauth_token")
	}
	if token == "" {
		token = os.Getenv("GITHUB_OAUTH_TOKEN")
	}

	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "GitHub authorization token required"})
		return
	}

	branches, err := github.ListRepoBranches(token, owner, repoName)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(branches)
}

// Gorilla WebSocket Upgrader
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Local portal simplicity
	},
}

// HandleListProjects returns all projects from SQLite
func (ctx *ServerContext) HandleListProjects(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	list, err := ctx.Store.ListProjects()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(list)
}

// HandleProvisionVPS initiates background VPS provisioning
func (ctx *ServerContext) HandleProvisionVPS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		ServerID      int64  `json:"server_id"`
		IPAddress     string `json:"ip_address"`
		SSHPort       int    `json:"ssh_port"`
		SSHUser       string `json:"ssh_user"`
		AuthMethod    string `json:"auth_method"`
		Password      string `json:"password"`
		PrivateKey    string `json:"private_key"`
		InstallDocker bool   `json:"install_docker"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request payload"})
		return
	}

	var ip string
	var port int
	var user string
	var auth string
	var pass string
	var pkey string

	if req.ServerID > 0 {
		srv, err := ctx.Store.GetServer(req.ServerID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Server not found"})
			return
		}
		ip = srv.IPAddress
		port = srv.SSHPort
		user = srv.SSHUser
		auth = "key"
		pkey = srv.SSHPrivateKey
	} else {
		ip = req.IPAddress
		port = req.SSHPort
		user = req.SSHUser
		auth = req.AuthMethod
		pass = req.Password
		pkey = req.PrivateKey
	}

	if port <= 0 {
		port = 22
	}
	if user == "" {
		user = "root"
	}

	jobID := fmt.Sprintf("provision-%s", ip)
	job := ctx.Jobs.GetOrCreateJob(jobID)

	go func() {
		job.Mu.Lock()
		job.Logs = nil // Clear history
		job.Mu.Unlock()

		job.AddLog("[System] Establishing connection to VPS...")
		client, err := connectSSHClient(ip, port, user, auth, pass, pkey)
		if err != nil {
			job.AddLog("[Error] Failed to connect: " + err.Error())
			return
		}
		defer client.Close()

		privKey, pubKey, err := generateSSHKeyPair()
		if err != nil {
			job.AddLog("[Error] Failed to generate SSH keypair: " + err.Error())
			return
		}

		err = internalssh.BootstrapVPS(client, req.InstallDocker, pubKey, func(line string) {
			job.AddLog(line)
		})

		if err != nil {
			job.AddLog("[Error] Bootstrapping failed: " + err.Error())
			return
		}

		serverID, err := ctx.Store.SaveServer(db.Server{
			Name:          fmt.Sprintf("vps-%s", ip),
			IPAddress:     ip,
			SSHPort:       port,
			SSHUser:       "deployer",
			SSHPrivateKey: privKey,
		})
		if err != nil {
			job.AddLog("[Warning] Bootstrapped successfully but failed to save server credentials: " + err.Error())
		} else {
			job.AddLog(fmt.Sprintf("[System] Bootstrapped server successfully saved with ID: %d", serverID))
		}
	}()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "started",
		"job_id": jobID,
	})
}

// HandleProvisionLogsStream streams VPS bootstrap log feeds over WebSocket
func (ctx *ServerContext) HandleProvisionLogsStream(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ip := r.URL.Query().Get("ip")
	jobID := fmt.Sprintf("provision-%s", ip)
	job := ctx.Jobs.GetOrCreateJob(jobID)

	// Stream historical logs first
	for _, line := range job.GetLogs() {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
			return
		}
	}

	listenerID := fmt.Sprintf("%p", conn)
	ch := job.RegisterListener(listenerID)
	defer job.UnregisterListener(listenerID)

	for line := range ch {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
			return
		}
	}
}

// HandleDeployLogsStream streams project deployment setup progress log feeds over WebSocket
func (ctx *ServerContext) HandleDeployLogsStream(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	projectName := r.URL.Query().Get("project_name")
	jobID := fmt.Sprintf("deploy-%s", projectName)
	job := ctx.Jobs.GetOrCreateJob(jobID)

	// Stream historical logs first
	for _, line := range job.GetLogs() {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
			return
		}
	}

	listenerID := fmt.Sprintf("%p", conn)
	ch := job.RegisterListener(listenerID)
	defer job.UnregisterListener(listenerID)

	for line := range ch {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
			return
		}
	}
}

// HandleDeployTrigger coordinates hot-swap CD deploy triggers from CI/CD runners
func (ctx *ServerContext) HandleDeployTrigger(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	repo := r.URL.Query().Get("repo")
	if repo == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing parameter 'repo'"})
		return
	}

	var req struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request payload"})
		return
	}

	if req.SHA == "" {
		req.SHA = "latest"
	}

	proj, err := ctx.Store.GetProjectByRepo(repo)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Project not found for repo: " + repo})
		return
	}

	srv, err := ctx.Store.GetServer(proj.ServerID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to load project server details"})
		return
	}

	jobID := fmt.Sprintf("project-%d", proj.ID)
	job := ctx.Jobs.GetOrCreateJob(jobID)

	go func() {
		job.Mu.Lock()
		job.Logs = nil // Clear history
		job.Mu.Unlock()

		image := fmt.Sprintf("ghcr.io/%s:%s", strings.ToLower(proj.GitHubRepo), req.SHA)
		err := ctx.performHotSwap(proj, srv, image, job)
		if err != nil {
			job.AddLog("[Error] Deployment failed: " + err.Error())
		}
	}()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "triggered",
		"project_id": proj.ID,
		"job_id":     jobID,
	})
}

// HandleProjectLogsStream streams deploy or rollback log feeds over WebSocket
func (ctx *ServerContext) HandleProjectLogsStream(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	idStr := chi.URLParam(r, "id")
	jobID := fmt.Sprintf("project-%s", idStr)
	job := ctx.Jobs.GetOrCreateJob(jobID)

	for _, line := range job.GetLogs() {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
			return
		}
	}

	listenerID := fmt.Sprintf("%p", conn)
	ch := job.RegisterListener(listenerID)
	defer job.UnregisterListener(listenerID)

	for line := range ch {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
			return
		}
	}
}

// HandleRollbackProject processes manual version rollbacks from dashboard actions
func (ctx *ServerContext) HandleRollbackProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid project ID"})
		return
	}

	var req struct {
		TargetImage string `json:"target_image"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request payload"})
		return
	}

	if req.TargetImage == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Target image is required"})
		return
	}

	proj, err := ctx.Store.GetProject(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Project not found"})
		return
	}

	srv, err := ctx.Store.GetServer(proj.ServerID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to load project server details"})
		return
	}

	jobID := fmt.Sprintf("project-%d", proj.ID)
	job := ctx.Jobs.GetOrCreateJob(jobID)

	go func() {
		job.Mu.Lock()
		job.Logs = nil // Clear history
		job.Mu.Unlock()

		err := ctx.performHotSwap(proj, srv, req.TargetImage, job)
		if err != nil {
			job.AddLog("[Error] Rollback failed: " + err.Error())
		}
	}()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "triggered",
		"project_id": proj.ID,
		"job_id":     jobID,
	})
}

// HandleDeleteProject removes a project configuration from the database.
func (ctx *ServerContext) HandleDeleteProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid project ID"})
		return
	}

	// Verify project exists
	_, err = ctx.Store.GetProject(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Project not found"})
		return
	}

	err = ctx.Store.DeleteProject(id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to delete project: " + err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// connectSSHClient establishes an SSH client connection
func connectSSHClient(ip string, port int, user string, authMethod string, password string, privateKey string) (*cryptossh.Client, error) {
	var authMethods []cryptossh.AuthMethod

	if authMethod == "password" {
		authMethods = append(authMethods, cryptossh.Password(password))
	} else if authMethod == "key" {
		signer, err := cryptossh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, cryptossh.PublicKeys(signer))
	} else {
		return nil, fmt.Errorf("unsupported auth method: %s", authMethod)
	}

	config := &cryptossh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, err
	}

	sshConn, chans, reqs, err := cryptossh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cryptossh.NewClient(sshConn, chans, reqs), nil
}

// performHotSwap executes the hot-swap zero-downtime deployment sequence on the remote host
func (ctx *ServerContext) performHotSwap(proj db.Project, srv db.Server, image string, job *Job) error {
	job.AddLog(fmt.Sprintf("[System] Establishing SSH connection to target VPS (%s)...", srv.IPAddress))
	client, err := connectSSHClient(srv.IPAddress, srv.SSHPort, srv.SSHUser, "key", "", srv.SSHPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to connect to VPS: %w", err)
	}
	defer client.Close()

	portA := proj.AppPort
	portB := proj.AppPort + 1
	if portA <= 0 {
		portA = 3000
		portB = 3001
	}

	targetPort := portA
	if proj.ActivePort == portA {
		targetPort = portB
	}

	// Authenticate with GHCR using saved github_oauth_token if present
	parts := strings.Split(proj.GitHubRepo, "/")
	owner := parts[0]
	token, _ := ctx.Store.GetSetting("github_oauth_token")
	if token == "" {
		token = os.Getenv("GITHUB_OAUTH_TOKEN")
	}
	if token != "" {
		job.AddLog("[Docker] Authenticating with GitHub Container Registry (ghcr.io)...")
		loginCmd := fmt.Sprintf("echo %q | docker login ghcr.io -u %q --password-stdin", token, owner)
		err = internalssh.RunCommandStream(client, loginCmd, func(line string) {
			if !strings.Contains(line, token) {
				job.AddLog("[Docker] " + line)
			}
		})
		if err != nil {
			job.AddLog("[Warning] GHCR authentication failed: " + err.Error() + ". Attempting pull anyway...")
		}
	}

	job.AddLog(fmt.Sprintf("[Docker] Pulling image: %s...", image))
	pullCmd := fmt.Sprintf("docker pull %s", image)
	err = internalssh.RunCommandStream(client, pullCmd, func(line string) {
		job.AddLog("[Docker] " + line)
	})
	if err != nil {
		return fmt.Errorf("docker pull failed: %w", err)
	}

	cleanName := cleanProjectName(proj.ProjectName)
	newContainerName := fmt.Sprintf("shipdude-%s-%d", cleanName, targetPort)
	oldContainerName := ""
	if proj.ActivePort > 0 {
		oldContainerName = fmt.Sprintf("shipdude-%s-%d", cleanName, proj.ActivePort)
	}

	job.AddLog(fmt.Sprintf("[Docker] Removing pre-existing container %s if present...", newContainerName))
	_ = internalssh.RunCommandStream(client, fmt.Sprintf("docker rm -f %s", newContainerName), func(line string) {})

	job.AddLog(fmt.Sprintf("[Docker] Launching new container %s on port %d...", newContainerName, targetPort))
	runCmd := fmt.Sprintf("docker run -d --name %s --restart unless-stopped -p %d:%d -e PORT=%d %s", newContainerName, targetPort, proj.AppPort, proj.AppPort, image)
	err = internalssh.RunCommandStream(client, runCmd, func(line string) {
		job.AddLog("[Docker] " + line)
	})
	if err != nil {
		return fmt.Errorf("docker run failed: %w", err)
	}

	job.AddLog("[System] Waiting for application to accept HTTP connections...")
	isHealthy := false
	for i := 0; i < 30; i++ {
		time.Sleep(2 * time.Second)
		checkCmd := fmt.Sprintf("curl -s -o /dev/null -w \"%%{http_code}\" http://localhost:%d/", targetPort)
		
		var httpCode string
		_ = internalssh.RunCommandStream(client, checkCmd, func(line string) {
			httpCode = strings.TrimSpace(line)
		})

		if httpCode != "" && httpCode != "000" {
			job.AddLog(fmt.Sprintf("[System] Application responded with status: %s. Health check passed!", httpCode))
			isHealthy = true
			break
		}
		job.AddLog(fmt.Sprintf("[System] Health check attempt %d/30: waiting for port %d to listen...", i+1, targetPort))
	}

	if !isHealthy {
		job.AddLog("[Error] Health check timed out after 60s. Rolling back container launch...")
		_ = internalssh.RunCommandStream(client, fmt.Sprintf("docker rm -f %s", newContainerName), func(string) {})
		return errors.New("container health check failed")
	}

	job.AddLog("[Caddy] Regenerating Caddyfile configurations...")
	err = ctx.regenerateCaddyfile(client, srv.ID, srv.IPAddress, proj.ID, targetPort)
	if err != nil {
		return fmt.Errorf("caddyfile regeneration failed: %w", err)
	}

	job.AddLog("[Caddy] Reloading Caddy Ingress Gateway...")
	reloadCmd := "docker exec shipdude-caddy caddy reload --config /etc/caddy/Caddyfile"
	err = internalssh.RunCommandStream(client, reloadCmd, func(line string) {
		job.AddLog("[Caddy] " + line)
	})
	if err != nil {
		job.AddLog(fmt.Sprintf("[Warning] Caddy reload returned error: %s. Continuing...", err.Error()))
	}

	if oldContainerName != "" && oldContainerName != newContainerName {
		job.AddLog(fmt.Sprintf("[Docker] Pruning old container %s...", oldContainerName))
		_ = internalssh.RunCommandStream(client, fmt.Sprintf("docker rm -f %s", oldContainerName), func(line string) {})
	}

	err = ctx.Store.UpdateProjectActiveState(proj.ID, targetPort, image)
	if err != nil {
		job.AddLog("[Warning] Failed to update project state in database: " + err.Error())
	}

	job.AddLog("[System] Zero-Downtime Hot-Swap complete!")
	return nil
}

// regenerateCaddyfile rewrites the /var/lib/shipdude/caddy/Caddyfile configuration to map upstreams
func (ctx *ServerContext) regenerateCaddyfile(client *cryptossh.Client, serverID int64, serverIP string, targetProjectID int64, targetPort int) error {
	projects, err := ctx.Store.ListProjects()
	if err != nil {
		return err
	}

	var sb strings.Builder
	sb.WriteString("# ShipDude Ingress Gateway Config\n\n")

	for _, p := range projects {
		if p.ServerID != serverID {
			continue
		}

		port := p.ActivePort
		if p.ID == targetProjectID {
			port = targetPort
		}

		if port <= 0 {
			continue
		}

		domain := p.Domain
		if domain == "" {
			domain = fmt.Sprintf("%s.%s.sslip.io", cleanProjectName(p.ProjectName), serverIP)
		}

		sb.WriteString(fmt.Sprintf("%s {\n", domain))
		sb.WriteString(fmt.Sprintf("    reverse_proxy localhost:%d\n", port))
		sb.WriteString("}\n\n")
	}

	caddyfileContent := sb.String()

	b64Content := base64.StdEncoding.EncodeToString([]byte(caddyfileContent))
	writeCmd := fmt.Sprintf("echo '%s' | base64 -d | sudo tee /var/lib/shipdude/caddy/Caddyfile >/dev/null", b64Content)
	
	err = internalssh.RunCommandStream(client, writeCmd, func(string) {})
	if err != nil {
		return err
	}

	// Copy to Caddy container to support DIND / simulator host-mount limitations
	cpCmd := "docker cp /var/lib/shipdude/caddy/Caddyfile shipdude-caddy:/etc/caddy/Caddyfile"
	_ = internalssh.RunCommandStream(client, cpCmd, func(string) {})
	return nil
}

// cleanProjectName formats project names to be docker-safe
func cleanProjectName(name string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			sb.WriteRune(r)
		} else if r == ' ' || r == '_' {
			sb.WriteRune('-')
		}
	}
	res := sb.String()
	if res == "" {
		res = "app"
	}
	return res
}
