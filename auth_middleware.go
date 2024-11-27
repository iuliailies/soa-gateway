package main

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const userIDKey = contextKey("user_id")

// Blocklist structure to store invalidated tokens
type Blocklist struct {
	mu       sync.Mutex
	tokens   map[string]time.Time // token -> expiration time
}

var blocklist = Blocklist{
	tokens: make(map[string]time.Time),
}

func (b *Blocklist) Add(token string, expiration time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens[token] = expiration
}

func (b *Blocklist) IsBlocked(token string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	expiration, exists := b.tokens[token]
	if !exists {
		return false
	}

	// If the expiration time has passed, remove the token
	if time.Now().After(expiration) {
		delete(b.tokens, token)
		return false
	}

	return true
}

// AuthMiddleware validates JWT and sets user ID in request context
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
            http.Error(w, "Missing or invalid token", http.StatusUnauthorized)
            return
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        claims := jwt.MapClaims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return JWTSecretKey, nil
        })
        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // Check if the token is in the blocklist
		if blocklist.IsBlocked(tokenString) {
			http.Error(w, "Unauthorized: token is invalidated", http.StatusUnauthorized)
			return
		}

        // Extract user ID from claims and add it to the context
        userID, ok := claims["user_id"].(float64)
        if !ok {
            http.Error(w, "Invalid token claims", http.StatusUnauthorized)
            return
        }
        
        ctx := context.WithValue(r.Context(), userIDKey, int(userID))
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// GetUserID retrieves the user ID from the request context
func GetUserID(r *http.Request) (int, bool) {
    userID, ok := r.Context().Value(userIDKey).(int)
    return userID, ok
}
