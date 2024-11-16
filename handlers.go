package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Credentials struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

type AuthResponse struct {
    UserID int `json:"user_id"`
}

// This handler will:
// Send the email and password to the expenses microservice to verify credentials.
// If the response is valid, generate a JWT token containing the user ID and return it.

// Login handler to authenticate the user and generate a JWT token
func Login(w http.ResponseWriter, r *http.Request) {
    var creds Credentials
    if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    // Make a request to the expenses microservice to verify credentials
    authResponse, err := authenticateWithExpensesMicroservice(creds)
    if err != nil {
        http.Error(w, "Authentication failed", http.StatusUnauthorized)
        return
    }

    token, err := generateJWT(authResponse.UserID)
    if err != nil {
        http.Error(w, "Could not create token", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// authenticateWithExpensesMicroservice sends the email and password to the auth microservice
func authenticateWithExpensesMicroservice(creds Credentials) (*AuthResponse, error) {
    // expensesMicroserviceUrl := "http://localhost:8081/auth/login" 
    expensesMicroserviceUrl := "http://host.docker.internal:8081/auth/login" 
    

    reqBody, _ := json.Marshal(creds)
    resp, err := http.Post(expensesMicroserviceUrl, "application/json", bytes.NewBuffer(reqBody))
    if err != nil || resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("authentication failed")
    }
    defer resp.Body.Close()

    var authResp AuthResponse
    if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
        return nil, err
    }
    return &authResp, nil
}

// generateJWT creates a JWT token with the user ID as a claim
func generateJWT(userID int) (string, error) {
    claims := jwt.MapClaims{
        "user_id": userID,
        "exp":     time.Now().Add(TokenExpiry).Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(JWTSecretKey)
}
