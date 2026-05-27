package ssh

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Diagnostics holds the results of the target VPS verification
type Diagnostics struct {
	Connected      bool   `json:"connected"`
	OS             string `json:"os"`
	DockerVersion  string `json:"docker_version"`
	ComposeVersion string `json:"compose_version"`
	HasSudo        bool   `json:"has_sudo"`
	InDockerGroup  bool   `json:"in_docker_group"`
	Bootstrapped   bool   `json:"bootstrapped"`
	Error          string `json:"error,omitempty"`
}

// ProbeCredentials contains the necessary details to connect to the target VPS
type ProbeCredentials struct {
	IPAddress  string `json:"ip_address"`
	Port       int    `json:"ssh_port"`
	User       string `json:"ssh_user"`
	AuthMethod string `json:"auth_method"` // "password" or "key"
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

// RunDiagnostics connects via SSH and checks VPS environment capabilities
func RunDiagnostics(creds ProbeCredentials) (*Diagnostics, error) {
	var authMethods []ssh.AuthMethod

	if creds.AuthMethod == "password" {
		authMethods = append(authMethods, ssh.Password(creds.Password))
	} else if creds.AuthMethod == "key" {
		signer, err := ssh.ParsePrivateKey([]byte(creds.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else {
		return nil, fmt.Errorf("unsupported auth method: %s", creds.AuthMethod)
	}

	config := &ssh.ClientConfig{
		User:            creds.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Setup for production known_hosts in later phase
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", creds.IPAddress, creds.Port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return &Diagnostics{Connected: false, Error: err.Error()}, nil
	}
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return &Diagnostics{Connected: false, Error: err.Error()}, nil
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	diag := &Diagnostics{Connected: true}

	// 1. Check OS Distribution
	osOut, err := runCommand(client, "cat /etc/os-release")
	if err == nil {
		diag.OS = parseOSRelease(osOut)
	} else {
		diag.OS = "Unknown OS"
	}

	// 2. Check Docker version
	dockerOut, err := runCommand(client, "docker --version")
	if err == nil {
		diag.DockerVersion = strings.TrimSpace(dockerOut)
	} else {
		diag.DockerVersion = "Not Installed"
	}

	// 3. Check Docker Compose version
	composeOut, err := runCommand(client, "docker compose version")
	if err == nil {
		diag.ComposeVersion = strings.TrimSpace(composeOut)
	} else {
		diag.ComposeVersion = "Not Installed"
	}

	// 4. Check permissions and groups
	groupsOut, err := runCommand(client, "groups")
	if err == nil {
		diag.InDockerGroup = strings.Contains(groupsOut, "docker")
	}

	sudoOut, err := runCommand(client, "sudo -n true")
	diag.HasSudo = (err == nil && !strings.Contains(sudoOut, "sudo: a password is required"))

	// 5. Check if already bootstrapped (has deployer user and shipdude-caddy container exists)
	deployerCheck, err := runCommand(client, "id -u deployer")
	hasDeployer := err == nil && strings.TrimSpace(deployerCheck) != ""

	caddyCheck, err := runCommand(client, "docker ps -a --filter 'name=shipdude-caddy' --format '{{.Names}}'")
	hasCaddy := err == nil && strings.Contains(caddyCheck, "shipdude-caddy")

	diag.Bootstrapped = hasDeployer && hasCaddy

	return diag, nil
}

func runCommand(client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(cmd)
	if err != nil {
		return stdout.String() + stderr.String(), err
	}

	return stdout.String(), nil
}

func parseOSRelease(output string) string {
	lines := strings.Split(output, "\n")
	var name, version string
	for _, line := range lines {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(line[12:], `"`)
		}
		if strings.HasPrefix(line, "NAME=") && name == "" {
			name = strings.Trim(line[5:], `"`)
		}
		if strings.HasPrefix(line, "VERSION=") && version == "" {
			version = strings.Trim(line[8:], `"`)
		}
	}
	if name != "" {
		if version != "" {
			return fmt.Sprintf("%s %s", name, version)
		}
		return name
	}
	return "Generic Linux"
}

// AddAuthorizedKey appends a public SSH key to the target server's authorized_keys file
func AddAuthorizedKey(creds ProbeCredentials, pubKey string) error {
	var authMethods []ssh.AuthMethod

	if creds.AuthMethod == "password" {
		authMethods = append(authMethods, ssh.Password(creds.Password))
	} else if creds.AuthMethod == "key" {
		signer, err := ssh.ParsePrivateKey([]byte(creds.PrivateKey))
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else {
		return fmt.Errorf("unsupported auth method: %s", creds.AuthMethod)
	}

	config := &ssh.ClientConfig{
		User:            creds.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", creds.IPAddress, creds.Port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect via SSH: %w", err)
	}
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return fmt.Errorf("failed to initialize SSH handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	// Ensure .ssh dir exists and append key safely
	cleanPubKey := strings.TrimSpace(pubKey)
	cmd := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", cleanPubKey)

	var stderr bytes.Buffer
	session.Stderr = &stderr
	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("failed to execute append command: %v (stderr: %s)", err, stderr.String())
	}

	return nil
}

