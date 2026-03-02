package session

import (
	"context"
	"fmt"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/google/uuid"
)

type sessionService struct {
	sessions SessionRepository
	hasher   Hasher
}

func New(sessions SessionRepository, hasher Hasher) *sessionService {
	return &sessionService{
		sessions: sessions,
		hasher:   hasher,
	}
}

func (ss *sessionService) Start(ctx context.Context, userID uuid.UUID, refreshToken string, expiresAt *time.Time) error {
	tokenHash, err := ss.hasher.Hash(refreshToken)
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	session := domain.Session{
		UserID:           userID,
		RefreshTokenHash: tokenHash,
		ExpiresAt:        expiresAt,
	}
	_, err = ss.sessions.Upsert(ctx, &session)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	return nil
}
func (ss *sessionService) Rotate(ctx context.Context, userID uuid.UUID, oldToken, newToken string, expirestAt *time.Time) error {
	oldHash, err := ss.hasher.Hash(oldToken)
	if err != nil {
		return fmt.Errorf("rotate: %w", err)
	}
	newHash, err := ss.hasher.Hash(newToken)
	if err != nil {
		return fmt.Errorf("rotate: %w", err)
	}

	session, err := ss.sessions.CompareAndSwapRefresh(ctx, userID, oldHash, newHash, expirestAt)
	if err != nil {
		return fmt.Errorf("rotate: %w", err)
	}
	if session == nil {
		return ErrTokenMismatch
	}

	return nil
}
func (ss *sessionService) Revoke(ctx context.Context, userID uuid.UUID, refreshToken string) error {
	err := ss.sessions.ClearRefreshByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	return err
}
