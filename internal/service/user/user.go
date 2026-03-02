package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/repository"
	"github.com/google/uuid"
)

type userService struct {
	users  UserRepository
	hasher Hasher
}

func New(users UserRepository, hasher Hasher) *userService {
	return &userService{
		users:  users,
		hasher: hasher,
	}
}

func (us *userService) Register(ctx context.Context, usernmae, password, role string) (*domain.User, error) {
	passwordHash, err := us.hasher.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	u := domain.User{
		Username:     usernmae,
		PasswordHash: passwordHash,
		Role:         role,
	}
	user, err := us.users.Create(ctx, &u)
	if err != nil {
		if errors.Is(err, repository.ErrAlreadyExists) {
			return nil, ErrUsernameTaken
		}
		return nil, fmt.Errorf("register: %w", err)
	}
	return user, nil
}

func (us *userService) ValidateCredentials(ctx context.Context, password, username string) (*domain.User, error) {
	user, err := us.users.FindByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("validateCredentials: %w", err)
	}

	valid, err := us.hasher.Verify(password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("validateCredentials: %w", err)
	}

	if !valid {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

func (us *userService) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	user, err := us.users.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getbyid: %w", err)
	}
	return user, nil
}
