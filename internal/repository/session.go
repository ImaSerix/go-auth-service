package repository

import (
	"context"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/google/uuid"
)

type SessionRepository interface {
	Create(ctx context.Context, session *domain.Session) (*domain.Session, error)
	FindByID(ctx context.Context, id uuid.UUID) (*domain.Session, error)
	FindByUserID(ctx context.Context, userID uuid.UUID) (*domain.Session, error)
	Update(ctx context.Context, session *domain.Session) error
	Delete(ctx context.Context, session *domain.Session) error
}
