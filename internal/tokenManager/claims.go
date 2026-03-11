package tokenmanager

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type accessClaims struct {
	UserID uuid.UUID `json:"id"`
	jwt.RegisteredClaims
}

type refreshClaims struct {
	UserID uuid.UUID `json:"id"`
	jwt.RegisteredClaims
}
