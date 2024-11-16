package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const userIDKey = contextKey("user_id")

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

        // Extract user ID from claims and add it to the context // TODO: what is a contetx?
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
