package main

import (
    "os"
    "time"
)

var (
    JWTSecretKey = []byte(os.Getenv("JWT_SECRET_KEY")) // Load from environment variable
    TokenExpiry  = time.Hour * 24                       // Token expiration (24 hours)
)
