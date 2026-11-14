package outbox_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/service/outbox"
	"github.com/google/uuid"
)

type receivedRequest struct {
	Method      string
	Path        string
	ContentType string
	Body        map[string]string
}

// fakeMessage is a stand-in for the Message service: it records requests and
// answers with the status chosen by the test for the user ID.
type fakeMessage struct {
	mu       sync.Mutex
	requests []receivedRequest
	status   func(userID string) int
}

func (fm *fakeMessage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)

	fm.mu.Lock()
	fm.requests = append(fm.requests, receivedRequest{
		Method:      r.Method,
		Path:        r.URL.Path,
		ContentType: r.Header.Get("Content-Type"),
		Body:        body,
	})
	status := fm.status(body["user_id"])
	fm.mu.Unlock()

	w.WriteHeader(status)
}

func (fm *fakeMessage) setStatus(status func(userID string) int) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.status = status
}

func (fm *fakeMessage) received() []receivedRequest {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return append([]receivedRequest(nil), fm.requests...)
}

func always(status int) func(string) int {
	return func(string) int { return status }
}

func newEntry(id int64) domain.OutboxEntry {
	return domain.OutboxEntry{ID: id, UserID: uuid.New(), Username: fmt.Sprintf("user%d", id)}
}

func TestDeliver_Created(t *testing.T) {
	msg := &fakeMessage{status: always(http.StatusCreated)}
	srv := httptest.NewServer(msg)
	defer srv.Close()

	repo := &fakeOutboxRepository{}
	entry := newEntry(1)
	repo.add(entry)

	outbox.New(repo, srv.URL).Deliver(t.Context())

	got := repo.get(1)
	if !got.delivered {
		t.Fatal("expected entry to be delivered")
	}
	if got.entry.Attempts != 1 {
		t.Fatalf("expected 1 attempt, got %d", got.entry.Attempts)
	}

	reqs := msg.received()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Method != http.MethodPost || reqs[0].Path != "/internal/users" {
		t.Fatalf("expected POST /internal/users, got %s %s", reqs[0].Method, reqs[0].Path)
	}
	if reqs[0].ContentType != "application/json" {
		t.Fatalf("expected json content type, got %q", reqs[0].ContentType)
	}
	if len(reqs[0].Body) != 2 || reqs[0].Body["user_id"] != entry.UserID.String() || reqs[0].Body["username"] != entry.Username {
		t.Fatalf("unexpected request body: %v", reqs[0].Body)
	}
}

func TestDeliver_TrailingSlashInURL(t *testing.T) {
	msg := &fakeMessage{status: always(http.StatusCreated)}
	srv := httptest.NewServer(msg)
	defer srv.Close()

	repo := &fakeOutboxRepository{}
	repo.add(newEntry(1))

	outbox.New(repo, srv.URL+"/").Deliver(t.Context())

	reqs := msg.received()
	if len(reqs) != 1 || reqs[0].Path != "/internal/users" {
		t.Fatalf("expected one request to /internal/users, got %v", reqs)
	}
}

// Message answers 409 when it already has the user: a repeated delivery is a success.
func TestDeliver_Conflict(t *testing.T) {
	msg := &fakeMessage{status: always(http.StatusConflict)}
	srv := httptest.NewServer(msg)
	defer srv.Close()

	repo := &fakeOutboxRepository{}
	repo.add(newEntry(1))

	outbox.New(repo, srv.URL).Deliver(t.Context())

	if !repo.get(1).delivered {
		t.Fatal("expected entry to be delivered on 409")
	}
}

func TestDeliver_FailureThenRetry(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadRequest, http.StatusOK, http.StatusNotFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			msg := &fakeMessage{status: always(status)}
			srv := httptest.NewServer(msg)
			defer srv.Close()

			repo := &fakeOutboxRepository{}
			repo.add(newEntry(1))
			svc := outbox.New(repo, srv.URL)

			svc.Deliver(t.Context())
			svc.Deliver(t.Context())

			got := repo.get(1)
			if got.delivered {
				t.Fatalf("expected entry to stay undelivered on %d", status)
			}
			if got.entry.Attempts != 2 {
				t.Fatalf("expected 2 attempts, got %d", got.entry.Attempts)
			}

			msg.setStatus(always(http.StatusCreated))
			svc.Deliver(t.Context())

			got = repo.get(1)
			if !got.delivered {
				t.Fatal("expected entry to be delivered after retry")
			}
			if got.entry.Attempts != 3 {
				t.Fatalf("expected 3 attempts, got %d", got.entry.Attempts)
			}

			// A delivered entry is not sent again.
			svc.Deliver(t.Context())
			if n := len(msg.received()); n != 3 {
				t.Fatalf("expected 3 requests, got %d", n)
			}
		})
	}
}

func TestDeliver_MessageUnavailable(t *testing.T) {
	msg := &fakeMessage{status: always(http.StatusCreated)}
	srv := httptest.NewServer(msg)
	url := srv.URL
	srv.Close() // nothing listens on this address anymore

	repo := &fakeOutboxRepository{}
	repo.add(newEntry(1))
	repo.add(newEntry(2))
	svc := outbox.New(repo, url)

	svc.Deliver(t.Context())

	for _, id := range []int64{1, 2} {
		got := repo.get(id)
		if got.delivered {
			t.Fatalf("entry %d: expected to stay undelivered", id)
		}
		if got.entry.Attempts != 1 {
			t.Fatalf("entry %d: expected 1 attempt, got %d", id, got.entry.Attempts)
		}
	}
}

// A failed entry does not stop the pass: the entries after it are still delivered.
func TestDeliver_FailedEntryDoesNotBlockOthers(t *testing.T) {
	repo := &fakeOutboxRepository{}
	first, bad, last := newEntry(1), newEntry(2), newEntry(3)
	repo.add(first)
	repo.add(bad)
	repo.add(last)

	msg := &fakeMessage{status: func(userID string) int {
		if userID == bad.UserID.String() {
			return http.StatusInternalServerError
		}
		return http.StatusCreated
	}}
	srv := httptest.NewServer(msg)
	defer srv.Close()

	outbox.New(repo, srv.URL).Deliver(t.Context())

	if !repo.get(1).delivered || !repo.get(3).delivered {
		t.Fatal("expected entries 1 and 3 to be delivered")
	}
	if repo.get(2).delivered {
		t.Fatal("expected entry 2 to stay undelivered")
	}

	reqs := msg.received()
	if len(reqs) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(reqs))
	}
	for i, e := range []domain.OutboxEntry{first, bad, last} {
		if reqs[i].Body["user_id"] != e.UserID.String() {
			t.Fatalf("request %d: expected entries in id order", i)
		}
	}
}

func TestDeliver_BatchLimit(t *testing.T) {
	msg := &fakeMessage{status: always(http.StatusCreated)}
	srv := httptest.NewServer(msg)
	defer srv.Close()

	repo := &fakeOutboxRepository{}
	for id := int64(1); id <= 101; id++ {
		repo.add(newEntry(id))
	}
	svc := outbox.New(repo, srv.URL)

	svc.Deliver(t.Context())

	if repo.lastLimit != 100 {
		t.Fatalf("expected limit 100, got %d", repo.lastLimit)
	}
	if n := len(msg.received()); n != 100 {
		t.Fatalf("expected 100 requests in one pass, got %d", n)
	}
	if repo.get(101).delivered {
		t.Fatal("expected entry 101 to wait for the next pass")
	}

	svc.Deliver(t.Context())
	if !repo.get(101).delivered {
		t.Fatal("expected entry 101 to be delivered by the second pass")
	}
}

func TestDeliver_ListError(t *testing.T) {
	msg := &fakeMessage{status: always(http.StatusCreated)}
	srv := httptest.NewServer(msg)
	defer srv.Close()

	repo := &fakeOutboxRepository{listErr: errors.New("db is down")}
	repo.add(newEntry(1))

	outbox.New(repo, srv.URL).Deliver(t.Context())

	if n := len(msg.received()); n != 0 {
		t.Fatalf("expected no requests, got %d", n)
	}
}

// Run delivers right after the start and returns when the context is cancelled.
func TestRun_DeliversAndStops(t *testing.T) {
	msg := &fakeMessage{status: always(http.StatusCreated)}
	srv := httptest.NewServer(msg)
	defer srv.Close()

	repo := &fakeOutboxRepository{}
	repo.add(newEntry(1))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		outbox.New(repo, srv.URL).Run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for !repo.get(1).delivered {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("expected entry to be delivered by the first pass")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("expected Run to return after cancel")
	}
}
