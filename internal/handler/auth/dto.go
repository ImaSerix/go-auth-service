package auth

import (
	"time"

	"github.com/google/uuid"
)

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}
type RegisterResponse struct {
	ID uuid.UUID `json:"id"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type LoginResponse struct {
	ID           uuid.UUID `json:"id"`
	AccessToken  string    `json:"accessToken"`
	AccessExp    time.Time `json:"accessExp"`
	RefreshToken string    `json:"refreshToken"`
	RefreshExp   time.Time `json:"refreshExp"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refreshToken"`
}
type LogoutResponse struct {
	Status string `json:"status"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}
type RefreshResponse struct {
	AccessToken  string    `json:"accessToken"`
	AccessExp    time.Time `json:"accessExp"`
	RefreshToken string    `json:"refreshToken"`
	RefreshExp   time.Time `json:"refreshExp"`
}

type ValidateResponse struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
	Roles    []string  `json:"roles"`
}
