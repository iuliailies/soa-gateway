package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Base URL for the backend microservice
    backendURL := "http://localhost:8081"
	// backendURL := "http://host.docker.internal:8081"

	// Create a reverse proxy for the backend
	backendProxy := newReverseProxy(backendURL)

	// Set up the router
	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, 
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		ExposedHeaders:   []string{"Content-Length"},
		AllowCredentials: true, 
		MaxAge:           300,  
	}))

	r.Use(middleware.Logger) // Log all requests

	// Public route for login
	r.Post("/auth/login", Login)

	// Protected routes
	r.Route("/api", func(api chi.Router) {
		api.Use(AuthMiddleware) // Apply the authentication middleware

		// Proxy routes to the backend
		api.Handle("/expenses", backendProxy)
		api.Handle("/users/*", backendProxy)
	})

	log.Println("Starting gateway on :8080")
	http.ListenAndServe(":8080", r)
}

// newReverseProxy creates a new reverse proxy for a given backend URL
// httputil.ReverseProxy handles request forwarding, header management, and response copying automatically.
func newReverseProxy(target string) *httputil.ReverseProxy {
	backend, err := url.Parse(target)
	if err != nil {
		log.Fatalf("Failed to parse backend URL %s: %v", target, err)
	}
    proxy := httputil.NewSingleHostReverseProxy(backend)

    // Customize the Director function to forward the user_id in the headers
    originalDirector := proxy.Director
    proxy.Director = func(req *http.Request) {
        originalDirector(req) // Retain default behavior

        // Extract user_id from context and add it to headers
        userID, ok := GetUserID(req)
        if ok {
            req.Header.Set("X-User-ID", strconv.Itoa(userID))
        }
    }

    return proxy
}
