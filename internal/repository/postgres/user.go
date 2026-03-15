package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

func (ur *UserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	var id uuid.UUID
	var createdAt time.Time
	err := ur.db.QueryRowContext(ctx, "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, created_at", user.Username, user.PasswordHash, user.Role).Scan(&id, &createdAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				return nil, repository.ErrAlreadyExists
			}
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}
	user.ID = id
	user.CreatedAt = createdAt
	return user, nil
}

func (ur *UserRepository) FindByUsername(ctx context.Context, username string) (*domain.User, error) {
	var user domain.User
	row := ur.db.QueryRowContext(ctx, "SELECT id, username, password_hash, role, created_at FROM users WHERE username = $1", username)

	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("finding user: %w", err)
	}
	return &user, nil
}

func (ur *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	var user domain.User
	row := ur.db.QueryRowContext(ctx, "SELECT id, username, password_hash, role, created_at FROM users WHERE id = $1", id)

	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("finding user: %w", err)
	}
	return &user, nil
}
