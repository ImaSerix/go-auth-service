package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/repository"
	"github.com/google/uuid"
)

type SessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{
		db: db,
	}
}

func (sr *SessionRepository) Upsert(ctx context.Context, session *domain.Session) error {
	_, err := sr.db.ExecContext(ctx, `INSERT INTO sessions (user_id, refresh_token_hash, expires_at, revoked_at) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id) DO UPDATE SET refresh_token_hash = $2, expires_at = $3`, session.UserID, session.RefreshTokenHash, session.ExpiresAt, session.RevokedAt)
	if err != nil {
		return fmt.Errorf("upser session: %w", err)
	}
	return nil
}
func (sr *SessionRepository) GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.Session, error) {
	var session domain.Session
	row := sr.db.QueryRowContext(ctx, "SELECT user_id, refresh_token_hash, expires_at, revoked_at FROM sessions WHERE user_id = $1", userID)

	if err := row.Scan(&session.UserID, &session.RefreshTokenHash, &session.ExpiresAt, &session.RevokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("find session: %w", err)
	}
	return &session, nil
}
func (sr *SessionRepository) SwapRefresh(ctx context.Context, userID uuid.UUID, newHash string, expiresAt *time.Time) error {
	res, err := sr.db.ExecContext(ctx, "UPDATE sessions SET refresh_token_hash = $1, expires_at = $2 WHERE user_id = $3", newHash, expiresAt, userID)
	if err != nil {
		return fmt.Errorf("swapRefresh: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("swapRefresh: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("swapRefresh: no session for user")
	}

	return nil
}
func (sr *SessionRepository) ClearRefreshByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := sr.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("clearRefreshByUserID: %w", err)
	}
	return nil
}
