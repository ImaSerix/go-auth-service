package auth

import (
	"time"

	"github.com/google/uuid"
)

type UserDTO struct {
	ID       uuid.UUID
	Username string
	Role     string
}

type TokenDTO struct {
	AccessToken  string
	RefreshToken string
	AccessExp    *time.Time
	RefreshExp   *time.Time
}

type AccessTokenDTO struct {
	AccessToken string
	AccessExp   *time.Time
}

type AccessTokenPayload struct {
	UserID uuid.UUID
}

type RefreshTokenDTO struct {
	RefreshToken string
	RefreshExp   *time.Time
}

type RefreshTokenPayload struct {
	UserID uuid.UUID
}
