package outbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/google/uuid"
)

const (
	pollInterval   = 5 * time.Second
	batchSize      = 100
	requestTimeout = 5 * time.Second
)

type outboxService struct {
	entries    OutboxRepository
	messageURL string
	client     *http.Client
}

// New returns a delivery service that sends registered users to the Message
// service at messageURL (base URL, for example http://message:8080).
func New(entries OutboxRepository, messageURL string) *outboxService {
	return &outboxService{
		entries:    entries,
		messageURL: strings.TrimRight(messageURL, "/"),
		client:     &http.Client{Timeout: requestTimeout},
	}
}

// Run delivers undelivered entries right away and then every pollInterval
// until ctx is cancelled.
func (obs *outboxService) Run(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		obs.Deliver(ctx)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Deliver makes one pass: takes up to batchSize undelivered entries in id order
// and tries to send each of them once. A failed entry is logged, stays
// undelivered and does not stop the pass.
func (obs *outboxService) Deliver(ctx context.Context) {
	entries, err := obs.entries.ListUndelivered(ctx, batchSize)
	if err != nil {
		log.Printf("outbox: list undelivered entries: %v", err)
		return
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}

		if err := obs.send(ctx, &entry); err != nil {
			log.Printf("outbox: deliver user %s (entry %d, attempt %d): %v", entry.UserID, entry.ID, entry.Attempts+1, err)
			if err := obs.entries.MarkFailed(ctx, entry.ID); err != nil {
				log.Printf("outbox: entry %d: %v", entry.ID, err)
			}
			continue
		}

		if err := obs.entries.MarkDelivered(ctx, entry.ID); err != nil {
			log.Printf("outbox: entry %d: %v", entry.ID, err)
		}
	}
}

type createUserRequest struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
}

// send calls POST /internal/users of the Message service. The user is
// delivered when Message answers 201 (created) or 409 (already has this user).
func (obs *outboxService) send(ctx context.Context, entry *domain.OutboxEntry) error {
	body, err := json.Marshal(createUserRequest{UserID: entry.UserID, Username: entry.Username})
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, obs.messageURL+"/internal/users", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := obs.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}
