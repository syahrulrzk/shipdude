package db

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStore_Operations(t *testing.T) {
	// 1. Setup temporary directory for DB file and key
	tmpDir, err := os.MkdirTemp("", "shipdude-db-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "shipdude.db")

	// 2. Initialize Store
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	// 3. Test Settings CRUD (Encrypted)
	t.Run("SettingsCRUD", func(t *testing.T) {
		err = store.SaveSetting("oauth_token", "github_pat_1234567")
		if err != nil {
			t.Fatalf("failed to save setting: %v", err)
		}

		val, err := store.GetSetting("oauth_token")
		if err != nil {
			t.Fatalf("failed to get setting: %v", err)
		}
		if val != "github_pat_1234567" {
			t.Errorf("expected 'github_pat_1234567', got '%s'", val)
		}

		// Test non-existent key returns empty string without error
		missing, err := store.GetSetting("non_existent")
		if err != nil {
			t.Fatalf("unexpected error getting missing key: %v", err)
		}
		if missing != "" {
			t.Errorf("expected empty string, got: %s", missing)
		}
	})

	// 4. Test Server CRUD (Encrypted SSH Key)
	t.Run("ServerCRUD", func(t *testing.T) {
		srv := Server{
			Name:          "Production VPS",
			IPAddress:     "103.187.22.44",
			SSHPort:       22,
			SSHUser:       "deployer",
			SSHPrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nMOCKKEYCONTENT\n-----END OPENSSH PRIVATE KEY-----",
		}

		srvID, err := store.SaveServer(srv)
		if err != nil {
			t.Fatalf("failed to save server: %v", err)
		}

		srvRead, err := store.GetServer(srvID)
		if err != nil {
			t.Fatalf("failed to read server: %v", err)
		}
		if srvRead.Name != srv.Name {
			t.Errorf("expected name '%s', got '%s'", srv.Name, srvRead.Name)
		}
		if srvRead.IPAddress != srv.IPAddress {
			t.Errorf("expected IP '%s', got '%s'", srv.IPAddress, srvRead.IPAddress)
		}
		if srvRead.SSHPrivateKey != srv.SSHPrivateKey {
			t.Errorf("decrypted private key mismatch. Got:\n%s", srvRead.SSHPrivateKey)
		}

		// Test listing
		servers, err := store.ListServers()
		if err != nil {
			t.Fatalf("failed to list servers: %v", err)
		}
		if len(servers) != 1 {
			t.Errorf("expected 1 server, got %d", len(servers))
		}
		if servers[0].SSHPrivateKey != srv.SSHPrivateKey {
			t.Errorf("listed server private key decrypted mismatch")
		}
	})

	// 5. Test Project CRUD (Plaintext)
	t.Run("ProjectCRUD", func(t *testing.T) {
		proj := Project{
			ServerID:       1,
			GitHubRepo:     "user4xn/my-app",
			GitHubBranch:   "main",
			ProjectName:    "App Service",
			DeploymentPath: "/var/www/my-app",
			StackType:      "node",
			StackVersion:   "20-alpine",
			AppPort:        3000,
		}

		projID, err := store.SaveProject(proj)
		if err != nil {
			t.Fatalf("failed to save project: %v", err)
		}

		projRead, err := store.GetProject(projID)
		if err != nil {
			t.Fatalf("failed to read project: %v", err)
		}
		if projRead.ProjectName != proj.ProjectName {
			t.Errorf("expected project name '%s', got '%s'", proj.ProjectName, projRead.ProjectName)
		}
		if projRead.AppPort != proj.AppPort {
			t.Errorf("expected port %d, got %d", proj.AppPort, projRead.AppPort)
		}

		// Test list projects
		projects, err := store.ListProjects()
		if err != nil {
			t.Fatalf("failed to list projects: %v", err)
		}
		if len(projects) != 1 {
			t.Errorf("expected 1 project, got %d", len(projects))
		}
	})
}
