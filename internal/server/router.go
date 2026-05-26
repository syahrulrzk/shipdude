package server

import (
	"net/http"
	"shipdude/internal/db"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// SetupRouter creates the Chi router and configures middleware and handlers
func SetupRouter(staticHandler http.Handler, dbStore *db.Store) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	ctx := NewServerContext(dbStore)

	// API Routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/vps/probe", ctx.HandleVPSProbe)
		r.Get("/vps/last-connection", ctx.HandleGetVPSLastConnection)
		r.Post("/vps/last-connection", ctx.HandlePostVPSLastConnection)
		r.Post("/projects/detect-stack", ctx.HandleStackDetect)

		// Settings & Auth Routes
		r.Get("/settings/github", ctx.HandleGetSettings)
		r.Post("/settings/github", ctx.HandlePostSettings)
		r.Get("/auth/github", ctx.HandleGitHubLogin)
		r.Get("/auth/github/callback", ctx.HandleGitHubCallback)

		// GitHub Repository Autocomplete
		r.Get("/github/repos", ctx.HandleGetRepos)
		r.Get("/github/user", ctx.HandleGetGitHubUser)
		r.Get("/github/branches", ctx.HandleGetBranches)
		r.Post("/github/disconnect", ctx.HandleGitHubDisconnect)

		// Deployment Setup
		r.Post("/projects/deploy", ctx.HandleDeployProject)
	})

	// Serve Static Files for Frontend SPA
	r.Handle("/*", staticHandler)

	return r
}
