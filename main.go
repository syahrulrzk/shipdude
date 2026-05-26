package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"shipdude/internal/server"
)

//go:embed web/*
var staticFS embed.FS

func main() {
	// Extract the web directory subdirectory from our embedded filesystem
	subFS, err := fs.Sub(staticFS, "web")
	if err != nil {
		log.Fatalf("failed to locate embedded static assets sub-directory: %v", err)
	}

	staticHandler := http.FileServer(http.FS(subFS))
	router := server.SetupRouter(staticHandler)

	port := ":8080"
	log.Printf("=============================================")
	log.Printf("  ShipDude Web Portal Starting...             ")
	log.Printf("  Access local portal at http://localhost%s  ", port)
	log.Printf("=============================================")

	if err := http.ListenAndServe(port, router); err != nil {
		log.Fatalf("Failed to bind server to port %s: %v", port, err)
	}
}
