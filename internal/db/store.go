package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Server represents a target VPS node managed by ShipDude.
type Server struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	IPAddress     string `json:"ip_address"`
	SSHPort       int    `json:"ssh_port"`
	SSHUser       string `json:"ssh_user"`
	SSHPrivateKey string `json:"ssh_private_key"`
}

// Project represents a deployed application container configuration.
type Project struct {
	ID             int64  `json:"id"`
	ServerID       int64  `json:"server_id"`
	GitHubRepo     string `json:"github_repo"`
	GitHubBranch   string `json:"github_branch"`
	ProjectName    string `json:"project_name"`
	DeploymentPath string `json:"deployment_path"`
	StackType      string `json:"stack_type"`
	StackVersion   string `json:"stack_version"`
	AppPort        int    `json:"app_port"`
}

// Store holds the database connection and encryption keys.
type Store struct {
	db     *sql.DB
	aesKey []byte
}

// NewStore initializes the SQLite database and ensures the schema is built.
func NewStore(configPath string) (*Store, error) {
	// 1. Ensure config directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// 2. Load or generate AES-256 key
	keyPath := filepath.Join(dir, "encryption.key")
	var aesKey []byte
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		aesKey = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
			return nil, fmt.Errorf("failed to generate encryption key: %w", err)
		}
		if err := os.WriteFile(keyPath, aesKey, 0600); err != nil {
			return nil, fmt.Errorf("failed to write encryption key: %w", err)
		}
	} else {
		aesKey, err = os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read encryption key: %w", err)
		}
		if len(aesKey) != 32 {
			return nil, fmt.Errorf("invalid encryption key length: expected 32, got %d", len(aesKey))
		}
	}

	// 3. Connect to SQLite
	db, err := sql.Open("sqlite", configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	s := &Store{
		db:     db,
		aesKey: aesKey,
	}

	// 4. Initialize schema tables
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to init schema: %w", err)
	}

	return s, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) initSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS servers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			ssh_port INTEGER DEFAULT 22,
			ssh_user TEXT DEFAULT 'root',
			ssh_private_key TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS projects (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id INTEGER NOT NULL,
			github_repo TEXT NOT NULL,
			github_branch TEXT DEFAULT 'main',
			project_name TEXT NOT NULL,
			deployment_path TEXT NOT NULL,
			stack_type TEXT NOT NULL,
			stack_version TEXT NOT NULL,
			app_port INTEGER NOT NULL,
			FOREIGN KEY(server_id) REFERENCES servers(id)
		);`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// Server CRUD with AES encryption for the private key
func (s *Store) SaveServer(srv Server) (int64, error) {
	encryptedKey, err := s.encryptString(srv.SSHPrivateKey)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt ssh key: %w", err)
	}

	res, err := s.db.Exec(
		`INSERT INTO servers (name, ip_address, ssh_port, ssh_user, ssh_private_key) VALUES (?, ?, ?, ?, ?)`,
		srv.Name, srv.IPAddress, srv.SSHPort, srv.SSHUser, encryptedKey,
	)
	if err != nil {
		return 0, err
	}

	return res.LastInsertId()
}

func (s *Store) GetServer(id int64) (Server, error) {
	var srv Server
	var encryptedKey string
	err := s.db.QueryRow(
		`SELECT id, name, ip_address, ssh_port, ssh_user, ssh_private_key FROM servers WHERE id = ?`, id,
	).Scan(&srv.ID, &srv.Name, &srv.IPAddress, &srv.SSHPort, &srv.SSHUser, &encryptedKey)

	if err != nil {
		return srv, err
	}

	decryptedKey, err := s.decryptString(encryptedKey)
	if err != nil {
		return srv, fmt.Errorf("failed to decrypt ssh key: %w", err)
	}

	srv.SSHPrivateKey = decryptedKey
	return srv, nil
}

func (s *Store) ListServers() ([]Server, error) {
	rows, err := s.db.Query(`SELECT id, name, ip_address, ssh_port, ssh_user, ssh_private_key FROM servers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Server
	for rows.Next() {
		var srv Server
		var encryptedKey string
		if err := rows.Scan(&srv.ID, &srv.Name, &srv.IPAddress, &srv.SSHPort, &srv.SSHUser, &encryptedKey); err != nil {
			return nil, err
		}

		decryptedKey, err := s.decryptString(encryptedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt ssh key: %w", err)
		}
		srv.SSHPrivateKey = decryptedKey
		list = append(list, srv)
	}
	return list, nil
}

// Project CRUD
func (s *Store) SaveProject(proj Project) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO projects (server_id, github_repo, github_branch, project_name, deployment_path, stack_type, stack_version, app_port) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		proj.ServerID, proj.GitHubRepo, proj.GitHubBranch, proj.ProjectName, proj.DeploymentPath, proj.StackType, proj.StackVersion, proj.AppPort,
	)
	if err != nil {
		return 0, err
	}

	return res.LastInsertId()
}

func (s *Store) GetProject(id int64) (Project, error) {
	var proj Project
	err := s.db.QueryRow(
		`SELECT id, server_id, github_repo, github_branch, project_name, deployment_path, stack_type, stack_version, app_port FROM projects WHERE id = ?`, id,
	).Scan(&proj.ID, &proj.ServerID, &proj.GitHubRepo, &proj.GitHubBranch, &proj.ProjectName, &proj.DeploymentPath, &proj.StackType, &proj.StackVersion, &proj.AppPort)

	return proj, err
}

func (s *Store) ListProjects() ([]Project, error) {
	rows, err := s.db.Query(`SELECT id, server_id, github_repo, github_branch, project_name, deployment_path, stack_type, stack_version, app_port FROM projects`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Project
	for rows.Next() {
		var proj Project
		if err := rows.Scan(&proj.ID, &proj.ServerID, &proj.GitHubRepo, &proj.GitHubBranch, &proj.ProjectName, &proj.DeploymentPath, &proj.StackType, &proj.StackVersion, &proj.AppPort); err != nil {
			return nil, err
		}
		list = append(list, proj)
	}
	return list, nil
}

// Settings CRUD (Encrypted storage)
func (s *Store) SaveSetting(key, val string) error {
	encryptedVal, err := s.encryptString(val)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`,
		key, encryptedVal,
	)
	return err
}

func (s *Store) GetSetting(key string) (string, error) {
	var encryptedVal string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&encryptedVal)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}

	return s.decryptString(encryptedVal)
}

// AES-256-GCM Encryption Helpers
func (s *Store) encryptString(plaintext string) (string, error) {
	block, err := aes.NewCipher(s.aesKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

func (s *Store) decryptString(ciphertextHex string) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(s.aesKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
