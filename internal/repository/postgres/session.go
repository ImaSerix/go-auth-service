package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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

func (sr *SessionRepository) Create(ctx context.Context, session *domain.Session) (*domain.Session, error) {
	_, err := sr.db.ExecContext(ctx, "INSERT INTO sessions (id, user_id, refresh_token_hash, expires_at, revoked_at) VALUES ($1, $2, $3, $4, $5)", session.ID, session.UserID, session.RefreshTokenHash, session.ExpiresAt, session.RevokedAt)
	if err != nil {
		return nil, fmt.Errorf("insert session: %w", err)
	}
	return session, nil
}
func (sr *SessionRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.Session, error) {
	var session domain.Session
	row := sr.db.QueryRowContext(ctx, "SELECT id, user_id, refresh_token_hash, expires_at, revoked_at FROM users WHERE id = $1", id)

	if err := row.Scan(&session.ID, &session.UserID, &session.RefreshTokenHash, &session.ExpiresAt, &session.RevokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("find session: %w", err)
	}
	return &session, nil
}

func (sr *SessionRepository) FindByUserID(ctx context.Context, userID uuid.UUID) (*domain.Session, error) {
	var session domain.Session
	row := sr.db.QueryRowContext(ctx, "SELECT id, user_id, refresh_token_hash, expires_at, revoked_at FROM users WHERE user_id = $1", userID)

	if err := row.Scan(&session.ID, &session.UserID, &session.RefreshTokenHash, &session.ExpiresAt, &session.RevokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("find session: %w", err)
	}
	return &session, nil
}

func (sr *SessionRepository) Update(ctx context.Context, session *domain.Session) error {
	_, err := sr.db.ExecContext(ctx, "UPDATE sessions SET expires_at = $1, revoked_at = $2, refresh_token_hash = $3 WHERE id = $4", session.ExpiresAt, session.RevokedAt, session.RefreshTokenHash, session.ID)

	if err != nil {
		return fmt.Errorf("update session: %w", err)
	}
	return nil
}
func (sr *SessionRepository) Delete(ctx context.Context, session *domain.Session) error {
	_, err := sr.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = $1", session.ID)

	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}
