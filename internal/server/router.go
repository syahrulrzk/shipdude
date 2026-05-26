package server

import (
	"encoding/json"
	"net/http"
	"shipdude/internal/github"
	"shipdude/internal/ssh"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// SetupRouter creates the Chi router and configures middleware and handlers
func SetupRouter(staticHandler http.Handler) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// API Routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/vps/probe", HandleVPSProbe)
		r.Post("/projects/detect-stack", HandleStackDetect)
	})

	// Serve Static Files for Frontend SPA
	r.Handle("/*", staticHandler)

	return r
}

// HandleVPSProbe processes VPS credential diagnostics requests
func HandleVPSProbe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var creds ssh.ProbeCredentials
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

	diags, err := ssh.RunDiagnostics(creds)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(diags)
}

// HandleStackDetect processes stack discovery requests
func HandleStackDetect(w http.ResponseWriter, r *http.Request) {
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

	info, err := github.DetectStack(req.Repo, req.Token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(info)
}
