package auth

import (
	"context"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/dto/auth"
	"github.com/google/uuid"
)

type AuthService interface {
	Register(ctx context.Context, in *RegisterInput) (*auth.UserDTO, error)
	Login(ctx context.Context, in *LoginInput) (*auth.UserDTO, *auth.TokenDTO, error)
	AuthViaToken(ctx context.Context, in *AuthViaTokenInput) (*auth.UserDTO, error)
	Refresh(ctx context.Context, in *RefreshInput) (*auth.TokenDTO, error)
	Logout(ctx context.Context, in *LogoutInput) error
}

type UserService interface {
	Register(ctx context.Context, username, password, role string) (*domain.User, error)
	ValidateCredentials(ctx context.Context, username, password string) (*domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

type SessionService interface {
	Start(ctx context.Context, userID uuid.UUID, refreshToken string, expiresAt *time.Time) error
	Rotate(ctx context.Context, userID uuid.UUID, oldToken, newToken string, expirestAt *time.Time) error
	Revoke(ctx context.Context, userID uuid.UUID, refreshToken string) error
}

type TokenManager interface {
	GenerateAccessToken(userID uuid.UUID) (*auth.AccessTokenDTO, error)
	GenerateRefreshToken(userID uuid.UUID) (*auth.RefreshTokenDTO, error)
	ParseAccessToken(token string) (*auth.AccessTokenPayload, error)
	ParseRefreshToken(token string) (*auth.RefreshTokenPayload, error)
}
