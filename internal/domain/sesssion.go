package domain

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	UserID           uuid.UUID
	RefreshTokenHash string
	ExpiresAt        *time.Time
	RevokedAt        *time.Time
}
