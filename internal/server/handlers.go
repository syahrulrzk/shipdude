package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"shipdude/internal/db"
	"shipdude/internal/github"
	internalssh "shipdude/internal/ssh"
	"sync"

	cryptossh "golang.org/x/crypto/ssh"
)

// ServerContext aggregates store and runtime state (like OAuth states).
type ServerContext struct {
	Store  *db.Store
	states sync.Map // keeps random OAuth state parameters to prevent CSRF
}

// NewServerContext initializes a context wrapper.
func NewServerContext(store *db.Store) *ServerContext {
	return &ServerContext{
		Store: store,
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

	oauthURL := fmt.Sprintf("%s/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=repo,write:packages,read:org&state=%s",
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

	// 1. Generate SSH deployment key pair in memory
	privKeyPEM, pubSSHKey, err := generateSSHKeyPair()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate deployment keys: " + err.Error()})
		return
	}

	// 2. Inject public key into target VPS ~/.ssh/authorized_keys
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
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to inject deployment public key to VPS: " + err.Error()})
		return
	}

	// 3. Save server details into SQLite (including encrypted Generated Private Key)
	serverID, err := ctx.Store.SaveServer(db.Server{
		Name:          req.ProjectName + "-node",
		IPAddress:     req.IPAddress,
		SSHPort:       req.SSHPort,
		SSHUser:       req.SSHUser,
		SSHPrivateKey: privKeyPEM,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to save server metadata: " + err.Error()})
		return
	}

	// 4. Upload generated SSH Private Key as a GitHub secret
	owner, repo, err := github.ParseRepoOwner(req.GitHubRepo)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	err = github.UploadRepoSecret(token, owner, repo, "SHIPDUDE_SSH_PRIVATE_KEY", privKeyPEM)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to configure GitHub Actions secrets: " + err.Error()})
		return
	}

	// 5. Generate and commit CI/CD workflow YAML configuration directly to repository
	yamlContent := generateWorkflowYAML(req.GitHubBranch, req.IPAddress, req.SSHPort, req.SSHUser, req.ProjectName)
	err = github.CommitWorkflowFile(token, owner, repo, req.GitHubBranch, yamlContent)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to commit workflow template: " + err.Error()})
		return
	}

	// 6. Save project metadata in SQLite
	projID, err := ctx.Store.SaveProject(db.Project{
		ServerID:       serverID,
		GitHubRepo:     req.GitHubRepo,
		GitHubBranch:   req.GitHubBranch,
		ProjectName:    req.ProjectName,
		DeploymentPath: req.DeploymentPath,
		StackType:      req.StackType,
		StackVersion:   req.StackVersion,
		AppPort:        req.AppPort,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to persist project metadata: " + err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Project deployed successfully! Auto CI/CD is active.",
		"project_id": projID,
		"server_id":  serverID,
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
func generateWorkflowYAML(branch, host string, port int, user, projectName string) string {
	return fmt.Sprintf(`name: ShipDude CD
on:
  push:
    branches:
      - "%s"

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
            curl -X POST -d '{"sha":"${{ github.sha }}"}' -H "Content-Type: application/json" http://localhost:8080/api/v1/projects/deploy-trigger?repo=${{ github.repository }}
`, branch, host, port, user)
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
