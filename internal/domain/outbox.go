package domain

import "github.com/google/uuid"

// OutboxEntry is a pending task "deliver this user to the Message service".
type OutboxEntry struct {
	ID       int64
	UserID   uuid.UUID
	Username string
	Attempts int
}
