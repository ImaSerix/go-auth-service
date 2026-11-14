package postgres_test

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/repository"
	"github.com/ImaSerix/password-safe-api/internal/repository/postgres"
	"github.com/ImaSerix/password-safe-api/internal/storage"
)

// newTestDB connects to the PostgreSQL database from TEST_DATABASE_URL, creates
// a schema of its own for the test, applies migrations/postgres to it and drops
// the schema when the test ends. The role must be allowed to create schemas.
// Without TEST_DATABASE_URL the test is skipped.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()

	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	dsn, err := url.Parse(raw)
	if err != nil {
		t.Fatal("TEST_DATABASE_URL is not a valid URL")
	}

	admin, err := storage.NewDBConnection(raw)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	schema := fmt.Sprintf("auth_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE")
		_ = admin.Close()
	})

	q := dsn.Query()
	q.Set("search_path", schema)
	dsn.RawQuery = q.Encode()
	db, err := storage.NewDBConnection(dsn.String())
	if err != nil {
		t.Fatalf("connect to test schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	files, err := filepath.Glob("../../../migrations/postgres/*.up.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations not found: %v", err)
	}
	sort.Strings(files)
	for _, file := range files {
		query, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read migration: %v", err)
		}
		if _, err := db.Exec(string(query)); err != nil {
			t.Fatalf("apply %s: %v", filepath.Base(file), err)
		}
	}
	return db
}

func count(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func newUser(username string) *domain.User {
	return &domain.User{Username: username, PasswordHash: "hash", Role: "user"}
}

func TestUserCreate_WritesUserAndOutboxEntry(t *testing.T) {
	db := newTestDB(t)
	users := postgres.NewUserRepository(db)

	u, err := users.Create(t.Context(), newUser("alice"))
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	entries, err := postgres.NewOutboxRepository(db).ListUndelivered(t.Context(), 100)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 outbox entry, got %d", len(entries))
	}
	if entries[0].UserID != u.ID || entries[0].Username != "alice" || entries[0].Attempts != 0 {
		t.Fatalf("unexpected outbox entry: %+v", entries[0])
	}
}

// The outbox entry cannot be written: the user must not appear either.
func TestUserCreate_NoUserWithoutOutboxEntry(t *testing.T) {
	db := newTestDB(t)
	users := postgres.NewUserRepository(db)

	if _, err := db.Exec("ALTER TABLE outbox RENAME TO outbox_away"); err != nil {
		t.Fatalf("rename outbox: %v", err)
	}

	if _, err := users.Create(t.Context(), newUser("alice")); err == nil {
		t.Fatal("expected error, got nil")
	}
	if n := count(t, db, "users"); n != 0 {
		t.Fatalf("expected no users, got %d", n)
	}
	if _, err := users.FindByUsername(t.Context(), "alice"); err != repository.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// The same registration succeeds once the outbox is back: nothing was left behind.
	if _, err := db.Exec("ALTER TABLE outbox_away RENAME TO outbox"); err != nil {
		t.Fatalf("rename outbox back: %v", err)
	}
	if _, err := users.Create(t.Context(), newUser("alice")); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if users, entries := count(t, db, "users"), count(t, db, "outbox"); users != 1 || entries != 1 {
		t.Fatalf("expected 1 user and 1 outbox entry, got %d and %d", users, entries)
	}
}

// The user cannot be written: no outbox entry must appear either.
func TestUserCreate_NoOutboxEntryWithoutUser(t *testing.T) {
	db := newTestDB(t)
	users := postgres.NewUserRepository(db)

	if _, err := users.Create(t.Context(), newUser("alice")); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	if _, err := users.Create(t.Context(), newUser("alice")); err != repository.ErrAlreadyExists {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
	if users, entries := count(t, db, "users"), count(t, db, "outbox"); users != 1 || entries != 1 {
		t.Fatalf("expected 1 user and 1 outbox entry, got %d and %d", users, entries)
	}
}

func TestOutbox_ListMarkDeliveredMarkFailed(t *testing.T) {
	db := newTestDB(t)
	users := postgres.NewUserRepository(db)
	entries := postgres.NewOutboxRepository(db)

	for _, username := range []string{"alice", "bobby", "carol"} {
		if _, err := users.Create(t.Context(), newUser(username)); err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
	}

	list, err := entries.ListUndelivered(t.Context(), 2)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(list) != 2 || list[0].Username != "alice" || list[1].Username != "bobby" || list[0].ID >= list[1].ID {
		t.Fatalf("expected the two oldest entries in id order, got %+v", list)
	}

	if err := entries.MarkDelivered(t.Context(), list[0].ID); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if err := entries.MarkFailed(t.Context(), list[1].ID); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	list, err = entries.ListUndelivered(t.Context(), 100)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(list) != 2 || list[0].Username != "bobby" || list[1].Username != "carol" {
		t.Fatalf("expected bobby and carol to stay undelivered, got %+v", list)
	}
	if list[0].Attempts != 1 || list[1].Attempts != 0 {
		t.Fatalf("expected attempts 1 and 0, got %d and %d", list[0].Attempts, list[1].Attempts)
	}

	var attempts int
	var delivered bool
	if err := db.QueryRow("SELECT attempts, delivered_at IS NOT NULL FROM outbox WHERE username = 'alice'").Scan(&attempts, &delivered); err != nil {
		t.Fatalf("read delivered entry: %v", err)
	}
	if !delivered || attempts != 1 {
		t.Fatalf("expected alice delivered after 1 attempt, got delivered=%v attempts=%d", delivered, attempts)
	}
}
