package session

import (
	"context"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/google/uuid"
)

type SessionRepository interface {
	Upsert(ctx context.Context, session *domain.Session) error
	GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.Session, error)
	SwapRefresh(ctx context.Context, userID uuid.UUID, newHash string, expiresAt *time.Time) error
	ClearRefreshByUserID(ctx context.Context, userID uuid.UUID) error
}

type Hasher interface {
	Hash(data string) (string, error)
	Verify(data, hash string) (bool, error)
}
