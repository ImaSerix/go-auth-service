package tokenmanager

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type accessClaims struct {
	UserID uuid.UUID `json:"id"`
	Role   string    `json:"role"`
	jwt.RegisteredClaims
}

type refreshClaims struct {
	UserID    uuid.UUID `json:"id"`
	SessionID uuid.UUID `json:"sessionId"`
	jwt.RegisteredClaims
}
