package user_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/repository"
	"github.com/ImaSerix/password-safe-api/internal/service/user"
	"github.com/google/uuid"
)

func RegisterTest_Success(t *testing.T) {
	usRepo := fakeUserRepository{
		err: nil,
		user: &domain.User{
			ID:           uuid.New(),
			Username:     "username",
			PasswordHash: "nice hash",
			Role:         "role",
			CreatedAt:    time.Now(),
		},
		called: false,
	}
	hasher := fakeHasher{
		err:    nil,
		called: false,
	}
	us := user.New(&usRepo, &hasher)

	resUser, err := us.Register(t.Context(), "username", "nice pass", "role")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if !hasher.called {
		t.Fatal("expected hasher to be called")
	}
	if !usRepo.called {
		t.Fatal("expected repo to be called")
	}
	if resUser == nil {
		t.Fatal("expected not nil user")
	}
}

func RegisterTest_HashError(t *testing.T) {
	usRepo := fakeUserRepository{
		err: nil,
		user: &domain.User{
			ID:           uuid.New(),
			Username:     "username",
			PasswordHash: "nice hash",
			Role:         "role",
			CreatedAt:    time.Now(),
		},
		called: false,
	}
	hasher := fakeHasher{
		err:    fmt.Errorf("bad error"),
		called: false,
	}
	us := user.New(&usRepo, &hasher)

	resUser, err := us.Register(t.Context(), "username", "nice pass", "role")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !hasher.called {
		t.Fatal("expected hasher to be called")
	}
	if usRepo.called {
		t.Fatal("expected repo not to be called")
	}
	if resUser != nil {
		t.Fatal("expected nil user")
	}
}

func RegisterTest_UsernameTaken(t *testing.T) {
	usRepo := fakeUserRepository{
		err: repository.ErrAlreadyExists,
		user: &domain.User{
			ID:           uuid.New(),
			Username:     "username",
			PasswordHash: "nice hash",
			Role:         "role",
			CreatedAt:    time.Now(),
		},
		called: false,
	}
	hasher := fakeHasher{
		err:    fmt.Errorf("bad error"),
		called: false,
	}
	us := user.New(&usRepo, &hasher)

	resUser, err := us.Register(t.Context(), "username", "nice pass", "role")
	if !errors.Is(err, user.ErrUsernameTaken) {
		t.Fatalf("expected 'ErrUsernameTaken' error, got %v", err)
	}
	if !hasher.called {
		t.Fatal("expected hasher to be called")
	}
	if !usRepo.called {
		t.Fatal("expected repo to be called")
	}
	if resUser != nil {
		t.Fatal("expected nil user")
	}
}
