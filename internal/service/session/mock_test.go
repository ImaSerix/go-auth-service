package session_test

import (
	"context"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/google/uuid"
)

type fakeSessionRepo struct {
	session *domain.Session
	err     error
	called  bool
}

func (fsr *fakeSessionRepo) Upsert(ctx context.Context, session *domain.Session) error {
	fsr.called = true
	fsr.session = session
	return fsr.err
}
func (fsr *fakeSessionRepo) GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.Session, error) {
	fsr.called = true
	if fsr.err != nil {
		return nil, fsr.err
	}
	return fsr.session, nil
}
func (fsr *fakeSessionRepo) SwapRefresh(ctx context.Context, userID uuid.UUID, newHash string, expiresAt *time.Time) error {
	fsr.called = true
	fsr.session.ExpiresAt = expiresAt
	fsr.session.RefreshTokenHash = newHash
	return fsr.err
}
func (fsr *fakeSessionRepo) ClearRefreshByUserID(ctx context.Context, userID uuid.UUID) error {
	fsr.called = true
	return fsr.err
}

type fakeHasher struct {
	err       error
	called    bool
	verifyRes bool
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
		return fh.verifyRes, fh.err
	}
	return fh.verifyRes, nil
}
