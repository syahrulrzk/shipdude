package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Helper to generate a temporary SSH RSA private key for the test server
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

func startMockSSHServer(t *testing.T, hostKey ssh.Signer, user string, password string) (string, io.Closer) {
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if conn.User() == user && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("auth failed")
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if conn.User() == user {
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
								cmd := string(req.Payload[4 : 4+req.Payload[3]]) // Parse command payload
								var response string

								if strings.Contains(cmd, "cat /etc/os-release") {
									response = "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n"
								} else if strings.Contains(cmd, "docker --version") {
									response = "Docker version 25.0.3, build f0df22d\n"
								} else if strings.Contains(cmd, "docker compose version") {
									response = "Docker Compose version v2.24.5\n"
								} else if strings.Contains(cmd, "groups") {
									response = "deployer docker admin\n"
								} else if strings.Contains(cmd, "sudo -n true") {
									// exit status 0 (no response body needed)
									response = ""
								}

								ch.Write([]byte(response))
								req.Reply(true, nil)

								// Send exit status message
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

func TestRunDiagnostics_Success(t *testing.T) {
	// 1. Setup mock SSH key and start mock server
	hostKey := generateTestHostKey(t)
	addr, server := startMockSSHServer(t, hostKey, "deployer", "mypassword")
	defer server.Close()

	// Parse host and port
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("Failed to parse address: %v", err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	// 2. Perform Probing
	creds := ProbeCredentials{
		IPAddress:  host,
		Port:       port,
		User:       "deployer",
		AuthMethod: "password",
		Password:   "mypassword",
	}

	diags, err := RunDiagnostics(creds)
	if err != nil {
		t.Fatalf("Unexpected error running diagnostics: %v", err)
	}

	// 3. Assertions
	if !diags.Connected {
		t.Errorf("Expected Connected=true, got false (error: %s)", diags.Error)
	}
	if diags.OS != "Ubuntu 22.04.3 LTS" {
		t.Errorf("Expected OS 'Ubuntu 22.04.3 LTS', got '%s'", diags.OS)
	}
	if !strings.Contains(diags.DockerVersion, "25.0.3") {
		t.Errorf("Expected Docker version containing '25.0.3', got '%s'", diags.DockerVersion)
	}
	if !strings.Contains(diags.ComposeVersion, "v2.24.5") {
		t.Errorf("Expected Compose version containing 'v2.24.5', got '%s'", diags.ComposeVersion)
	}
	if !diags.InDockerGroup {
		t.Errorf("Expected InDockerGroup=true, got false")
	}
	if !diags.HasSudo {
		t.Errorf("Expected HasSudo=true, got false")
	}
}

func TestRunDiagnostics_AuthFailure(t *testing.T) {
	hostKey := generateTestHostKey(t)
	addr, server := startMockSSHServer(t, hostKey, "deployer", "mypassword")
	defer server.Close()

	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	creds := ProbeCredentials{
		IPAddress:  host,
		Port:       port,
		User:       "deployer",
		AuthMethod: "password",
		Password:   "wrongpassword",
	}

	diags, err := RunDiagnostics(creds)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if diags.Connected {
		t.Errorf("Expected Connected=false on wrong password, got true")
	}
	if !strings.Contains(diags.Error, "ssh: handshake failed") {
		t.Errorf("Expected handshake failure error, got: %s", diags.Error)
	}
}

func TestRunDiagnostics_PrivateKeySuccess(t *testing.T) {
	// 1. Generate client private key PEM
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}
	clientPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
	})

	// 2. Setup host keys and start mock server
	hostKey := generateTestHostKey(t)
	addr, server := startMockSSHServer(t, hostKey, "deployer", "")
	defer server.Close()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("Failed to parse address: %v", err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	// 3. Perform Probing using key auth
	creds := ProbeCredentials{
		IPAddress:  host,
		Port:       port,
		User:       "deployer",
		AuthMethod: "key",
		PrivateKey: string(clientPEM),
	}

	diags, err := RunDiagnostics(creds)
	if err != nil {
		t.Fatalf("Unexpected error running diagnostics: %v", err)
	}

	// 4. Assertions
	if !diags.Connected {
		t.Errorf("Expected Connected=true via private key, got false (error: %s)", diags.Error)
	}
	if diags.OS != "Ubuntu 22.04.3 LTS" {
		t.Errorf("Expected OS 'Ubuntu 22.04.3 LTS', got '%s'", diags.OS)
	}
}

