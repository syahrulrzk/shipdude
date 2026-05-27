# 🚢 ShipDude

> Self-hosted, stateless DevOps orchestrator for zero-downtime deployments and automated GitHub Actions CI/CD pipelines.

ShipDude is a web-based tool that lets you deploy any Dockerized application to your own VPS — with a fully configured CI/CD pipeline, reverse proxy, and live monitoring — directly from your browser.

No cloud vendor lock-in. No monthly fees. Your infrastructure, your rules.

---

## ✨ Features

- **One-Click Deployment** — Connect your GitHub repo and VPS credentials, click deploy, done.
- **Auto CI/CD Pipeline** — Automatically commits a GitHub Actions workflow to your repository. Every push to your branch triggers a build, push to GHCR, and zero-downtime rollout to your VPS.
- **Zero-Downtime Hot-Swap** — New container spins up on an alternate port, passes a health check, then Caddy switches traffic over. Old container only gets killed after the new one is confirmed healthy.
- **Repository Stack Detection** — Automatically detects your tech stack (Go, Node.js, Python) and reads `EXPOSE` from your `Dockerfile` to prevent port mismatch crashes.
- **Live Monitoring Dashboard** — Stream CPU/RAM metrics and container logs in real-time directly in your browser via WebSocket.
- **Container Lifecycle Controls** — Start, Stop, and Restart your remote container with a single click.
- **Fail-Silent Webhooks** — If ShipDude is offline, your GitHub Actions pipeline stays green. The callback is wrapped with `|| true`.

---

## 📋 Requirements

### Your Machine (Controller)
- Any OS with a web browser
- Go 1.25+ (if building from source)

### Target VPS
- OS: **Ubuntu 20.04+** or **Debian** (recommended)
- SSH access (root or passwordless `sudo` user)
- Ports 22, 80, 443 open

### GitHub
- GitHub OAuth App configured (Client ID + Secret)
- Repository must have a `Dockerfile` at the root

---

## 🐳 Install via Docker Hub (Recommended)

The easiest way to run ShipDude. No Go installation required.

**1. Create a `docker-compose.yml`:**

```yaml
services:
  shipdude:
    image: user4xn/shipdude:latest
    container_name: shipdude
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - shipdude-config:/app/config

volumes:
  shipdude-config:
```

**2. Start it:**

```bash
docker compose up -d
```

**3. Open your browser:**

```
http://localhost:8080
```

Your configuration (SQLite database, credentials) is persisted in the `shipdude-config` named volume. It survives container restarts and updates.

**Updating to a new version:**

```bash
docker compose pull && docker compose up -d
```

---

## 🚀 Quick Start (Build from Source)

### Run from source

```bash
git clone https://github.com/user4xn/shipdude
cd shipdude
go run main.go
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

### Build binary

```bash
go build -o shipdude .
./shipdude
```

---

## ⚙️ Setup Guide (5 Steps)

**Step 1 — GitHub Auth**
Click the ⚙️ button (top right), enter your GitHub OAuth Client ID and Secret, save, then click **Authorize GitHub**.

**Step 2 — Connect VPS**
Enter your VPS Host IP, SSH Port, SSH User, and Private Key. Click **Test Connection** to verify, then **Bootstrap & Provision** to install Docker and Caddy on the target VPS.

**Step 3 — Analyze Repository**
Search or paste your repository name. Click **Analyze Tech Stack** — ShipDude will verify your repo has a `Dockerfile` and detect its exposed port.

**Step 4 — Deploy & Setup CI/CD**
Fill in your deployment name, port, and optionally a domain. Click **Bootstrap Deployment & Setup Auto-CI/CD**. ShipDude will:
- Generate an SSH key pair
- Register the public key on your VPS
- Encrypt and upload the private key to GitHub Secrets
- Commit the GitHub Actions workflow YAML to your repository

From this point, every push to your configured branch auto-deploys.

**Step 5 — Monitor**
Once active, click **📊 Open Monitoring Dashboard** on your project card to view live CPU/RAM metrics and container logs.

---

## 🏗️ Architecture

| Layer | Technology |
|-------|-----------|
| Backend | Go (`net/http`, `chi`, `gorilla/websocket`) |
| Database | SQLite (embedded, `modernc.org/sqlite`) |
| Frontend | Vanilla HTML + TailwindCSS (embedded via `go:embed`) |
| SSH | `golang.org/x/crypto/ssh` |
| Container Registry | GitHub Container Registry (GHCR) |
| Reverse Proxy | Caddy (auto-provisioned on VPS) |
| Binary Size | < 30MB |

---

## ⚠️ Known Limitations

- **Single VPS only** — Multi-node, Kubernetes, and Docker Swarm are not supported yet.
- **Local usage requires a tunnel** — GitHub Actions needs a public URL to send webhook callbacks. Use [ngrok](https://ngrok.com) or run ShipDude on a VPS itself.
- **Optimized for GHCR** — Docker Hub and custom registries require code customization.

---

## 🧪 Running Tests

```bash
go test ./...
```

All packages include integration tests with SSH mock servers.

---

## 📄 License

MIT — use it, fork it, ship it.

---

Built with ❤️ by [wildan-candra](https://github.com/user4xn) · [LinkedIn](https://www.linkedin.com/in/wildan-candra/)
