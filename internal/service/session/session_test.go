package session_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/repository"
	"github.com/ImaSerix/password-safe-api/internal/service/session"
	"github.com/google/uuid"
)

func TestStart_Success(t *testing.T) {
	sessionRepo := fakeSessionRepo{
		called: false,
	}
	hasher := fakeHasher{
		called: false,
	}

	ss := session.New(&sessionRepo, &hasher)

	id := uuid.New()
	exp := time.Now().Add(time.Hour * 6)
	err := ss.Start(t.Context(), id, "refresh token", &exp)

	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if !sessionRepo.called {
		t.Fatal("expected session repository to be called")
	}
	if !hasher.called {
		t.Fatal("expected hasher to be called")
	}
	if sessionRepo.session == nil {
		t.Fatal("expected session in repo be not nil")
	}
	if sessionRepo.session.UserID != id {
		t.Fatalf("expected session userID be %v, got %v", id, sessionRepo.session.UserID)
	}
	if *sessionRepo.session.ExpiresAt != exp {
		t.Fatalf("expected session userID be %v, got %v", sessionRepo.session.ExpiresAt, exp)
	}
	if sessionRepo.session.RefreshTokenHash == "refresh token" {
		t.Fatal("expected token to be hashed")
	}
}

func TestStart_HashError(t *testing.T) {
	sessionRepo := fakeSessionRepo{
		called: false,
	}
	hasher := fakeHasher{
		called: false,
		err:    errors.New("bad error"),
	}

	ss := session.New(&sessionRepo, &hasher)

	id := uuid.New()
	exp := time.Now().Add(time.Hour * 6)
	err := ss.Start(t.Context(), id, "refresh token", &exp)

	if err == nil {
		t.Fatal("expected internal error")
	}
	if !hasher.called {
		t.Fatal("expected hasher to be called")
	}
	if sessionRepo.called {
		t.Fatal("expected session repository not to be called")
	}
}

func TestRotate_Success(t *testing.T) {
	sessionRepo := fakeSessionRepo{
		called: false,
		session: &domain.Session{
			UserID:           uuid.New(),
			RefreshTokenHash: "old hash",
		},
	}
	hasher := fakeHasher{
		called: false,
	}

	ss := session.New(&sessionRepo, &hasher)

	exp := time.Now().Add(time.Hour * 6)
	err := ss.Rotate(t.Context(), sessionRepo.session.UserID, "old token", "new token", &exp)

	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if !sessionRepo.called {
		t.Fatal("expected session repository to be called")
	}
	if !hasher.called {
		t.Fatal("expected hasher to be called")
	}
	if sessionRepo.session == nil {
		t.Fatal("expected session in repo be not nil")
	}
	if sessionRepo.session.RefreshTokenHash == "old hash" {
		t.Fatal("expected token to be rotated")
	}
	if sessionRepo.session.RefreshTokenHash == "new token" {
		t.Fatal("expected token to be hashed")
	}
	if *sessionRepo.session.ExpiresAt != exp {
		t.Fatalf("expected session userID be %v, got %v", sessionRepo.session.ExpiresAt, exp)
	}
}

func TestRotate_HashError(t *testing.T) {
	sessionRepo := fakeSessionRepo{
		called: false,
		session: &domain.Session{
			UserID:           uuid.New(),
			RefreshTokenHash: "old hash",
		},
	}
	hasher := fakeHasher{
		called: false,
		err:    errors.New("bad error"),
	}

	ss := session.New(&sessionRepo, &hasher)

	exp := time.Now().Add(time.Hour * 6)
	err := ss.Rotate(t.Context(), sessionRepo.session.UserID, "old token", "new token", &exp)

	if err == nil {
		t.Fatal("expected internal error, got nil")
	}
	if !hasher.called {
		t.Fatal("expected hasher to be called")
	}
	if sessionRepo.called {
		t.Fatal("expected session repository not to be called")
	}
}

func TestRotate_TokenMismatch(t *testing.T) {
	sessionRepo := fakeSessionRepo{
		called: false,
		err:    repository.ErrInvalidRefresh,
		session: &domain.Session{
			UserID:           uuid.New(),
			RefreshTokenHash: "old hash",
		},
	}
	hasher := fakeHasher{
		called: false,
	}

	ss := session.New(&sessionRepo, &hasher)

	exp := time.Now().Add(time.Hour * 6)
	err := ss.Rotate(t.Context(), sessionRepo.session.UserID, "old token", "new token", &exp)

	if !errors.Is(err, session.ErrTokenMismatch) {
		t.Fatalf("expected %v error, got %v", session.ErrTokenMismatch, err)
	}
	if !sessionRepo.called {
		t.Fatal("expected session repository to be called")
	}
	if !hasher.called {
		t.Fatal("expected hasher to be called")
	}
}

func TestRevoke_Success(t *testing.T) {
	sessionRepo := fakeSessionRepo{
		called: false,
	}
	hasher := fakeHasher{
		called: false,
	}

	ss := session.New(&sessionRepo, &hasher)

	err := ss.Revoke(t.Context(), uuid.New(), "refresh token")

	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if !sessionRepo.called {
		t.Fatal("expected session repository to be called")
	}
}
