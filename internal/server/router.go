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
		r.Get("/projects/deploy/logs", ctx.HandleDeployLogsStream)

		// VPS Bootstrapping & Logs
		r.Post("/vps/provision", ctx.HandleProvisionVPS)
		r.Get("/vps/provision/logs", ctx.HandleProvisionLogsStream)

		// Deployment Triggers & Rollbacks & Monitoring
		r.Post("/projects/deploy-trigger", ctx.HandleDeployTrigger)
		r.Get("/projects/{id}/logs", ctx.HandleProjectLogsStream)
		r.Post("/projects/{id}/rollback", ctx.HandleRollbackProject)
		r.Delete("/projects/{id}", ctx.HandleDeleteProject)
		r.Get("/projects", ctx.HandleListProjects)
		r.Post("/projects/{id}/control", ctx.HandleControlProject)
		r.Get("/projects/{id}/telemetry", ctx.HandleProjectTelemetryStream)
		r.Get("/projects/{id}/container-logs", ctx.HandleProjectContainerLogsStream)
	})

	// Serve Static Files for Frontend SPA
	r.Handle("/*", staticHandler)

	return r
}
