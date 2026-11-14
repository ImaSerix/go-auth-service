package outbox

import (
	"context"

	"github.com/ImaSerix/password-safe-api/internal/domain"
)

type OutboxRepository interface {
	ListUndelivered(ctx context.Context, limit int) ([]domain.OutboxEntry, error)
	MarkDelivered(ctx context.Context, id int64) error
	MarkFailed(ctx context.Context, id int64) error
}
