package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ImaSerix/password-safe-api/internal/domain"
)

type OutboxRepository struct {
	db *sql.DB
}

func NewOutboxRepository(db *sql.DB) *OutboxRepository {
	return &OutboxRepository{
		db: db,
	}
}

// ListUndelivered returns up to limit entries that are not delivered yet, oldest first.
func (or *OutboxRepository) ListUndelivered(ctx context.Context, limit int) ([]domain.OutboxEntry, error) {
	rows, err := or.db.QueryContext(ctx, "SELECT id, user_id, username, attempts FROM outbox WHERE delivered_at IS NULL ORDER BY id LIMIT $1", limit)
	if err != nil {
		return nil, fmt.Errorf("list undelivered: %w", err)
	}
	defer rows.Close()

	var entries []domain.OutboxEntry
	for rows.Next() {
		var entry domain.OutboxEntry
		if err := rows.Scan(&entry.ID, &entry.UserID, &entry.Username, &entry.Attempts); err != nil {
			return nil, fmt.Errorf("list undelivered: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list undelivered: %w", err)
	}
	return entries, nil
}

// MarkDelivered records a successful attempt: the entry is not returned by ListUndelivered anymore.
func (or *OutboxRepository) MarkDelivered(ctx context.Context, id int64) error {
	_, err := or.db.ExecContext(ctx, "UPDATE outbox SET delivered_at = now(), attempts = attempts + 1 WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("mark delivered: %w", err)
	}
	return nil
}

// MarkFailed records a failed attempt: the entry stays undelivered.
func (or *OutboxRepository) MarkFailed(ctx context.Context, id int64) error {
	_, err := or.db.ExecContext(ctx, "UPDATE outbox SET attempts = attempts + 1 WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	return nil
}
