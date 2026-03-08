package user_test

import (
	"context"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/google/uuid"
)

type fakeUserRepository struct {
	err    error
	user   *domain.User
	called bool
}

func (fur *fakeUserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	fur.called = true
	if fur.err != nil {
		return nil, fur.err
	}
	return fur.user, nil
}
func (fur *fakeUserRepository) FindByUsername(ctx context.Context, username string) (*domain.User, error) {
	fur.called = true
	if fur.err != nil {
		return nil, fur.err
	}
	return fur.user, nil

}
func (fur *fakeUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	fur.called = true
	if fur.err != nil {
		return nil, fur.err
	}
	return fur.user, nil
}

type fakeHasher struct {
	err    error
	called bool
}

func (fh *fakeHasher) Hash(data string) (string, error) {
	fh.called = true
	if fh.err != nil {
		return "", fh.err
	}
	return "nice hash", nil
}
func (fh *fakeHasher) Verify(data, hash string) (bool, error) {
	fh.called = true
	if fh.err != nil {
		return false, fh.err
	}
	return true, nil
}
