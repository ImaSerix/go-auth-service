package outbox_test

import (
	"context"
	"sync"

	"github.com/ImaSerix/password-safe-api/internal/domain"
)

type fakeEntry struct {
	entry     domain.OutboxEntry
	delivered bool
}

// fakeOutboxRepository keeps entries in memory in id order.
type fakeOutboxRepository struct {
	mu        sync.Mutex
	entries   []*fakeEntry
	listErr   error
	lastLimit int
}

func (f *fakeOutboxRepository) add(entry domain.OutboxEntry) {
	f.entries = append(f.entries, &fakeEntry{entry: entry})
}

func (f *fakeOutboxRepository) get(id int64) fakeEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.entries {
		if e.entry.ID == id {
			return *e
		}
	}
	return fakeEntry{}
}

func (f *fakeOutboxRepository) ListUndelivered(ctx context.Context, limit int) ([]domain.OutboxEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastLimit = limit
	if f.listErr != nil {
		return nil, f.listErr
	}
	var res []domain.OutboxEntry
	for _, e := range f.entries {
		if !e.delivered && len(res) < limit {
			res = append(res, e.entry)
		}
	}
	return res, nil
}

func (f *fakeOutboxRepository) MarkDelivered(ctx context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.entries {
		if e.entry.ID == id {
			e.delivered = true
			e.entry.Attempts++
		}
	}
	return nil
}

func (f *fakeOutboxRepository) MarkFailed(ctx context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.entries {
		if e.entry.ID == id {
			e.entry.Attempts++
		}
	}
	return nil
}
