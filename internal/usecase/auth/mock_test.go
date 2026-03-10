package auth_test

import (
	"context"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/dto/auth"
	"github.com/google/uuid"
)

type fakeUserService struct {
	user   *domain.User
	err    error
	called bool
}

func (fus *fakeUserService) Register(ctx context.Context, username, password, role string) (*domain.User, error) {
	fus.called = true
	if fus.err != nil {
		return nil, fus.err
	}
	return fus.user, fus.err
}
func (fus *fakeUserService) ValidateCredentials(ctx context.Context, username, password string) (*domain.User, error) {
	fus.called = true
	if fus.err != nil {
		return nil, fus.err
	}
	return fus.user, fus.err
}
func (fus *fakeUserService) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	fus.called = true
	if fus.err != nil {
		return nil, fus.err
	}
	return fus.user, fus.err
}

type fakeSessionService struct {
	err    error
	called bool
}

func (fss *fakeSessionService) Start(ctx context.Context, userID uuid.UUID, refreshToken string, expiresAt *time.Time) error {
	fss.called = true
	return fss.err
}
func (fss *fakeSessionService) Rotate(ctx context.Context, userID uuid.UUID, oldToken, newToken string, expirestAt *time.Time) error {
	fss.called = true
	return fss.err
}
func (fss *fakeSessionService) Revoke(ctx context.Context, userID uuid.UUID, refreshToken string) error {
	fss.called = true
	return fss.err
}

type fakeTokenManager struct {
	userID uuid.UUID
	err    error
	called bool
}

func (ftm *fakeTokenManager) GenerateAccessToken(userID uuid.UUID) (*auth.AccessTokenDTO, error) {
	ftm.called = true
	if ftm.err != nil {
		return nil, ftm.err
	}

	t := time.Now().Add(time.Hour * 10)
	return &auth.AccessTokenDTO{
		AccessToken: "access token",
		AccessExp:   &t,
	}, nil
}
func (ftm *fakeTokenManager) GenerateRefreshToken(userID uuid.UUID) (*auth.RefreshTokenDTO, error) {
	ftm.called = true
	if ftm.err != nil {
		return nil, ftm.err
	}

	t := time.Now().Add(time.Hour * 10)
	return &auth.RefreshTokenDTO{
		RefreshToken: "refresh token",
		RefreshExp:   &t,
	}, nil
}
func (ftm *fakeTokenManager) ParseAccessToken(token string) (*auth.AccessTokenPayload, error) {
	ftm.called = true
	if ftm.err != nil {
		return nil, ftm.err
	}
	return &auth.AccessTokenPayload{
		UserID: ftm.userID,
	}, nil
}
func (ftm *fakeTokenManager) ParseRefreshToken(token string) (*auth.RefreshTokenPayload, error) {
	ftm.called = true
	if ftm.err != nil {
		return nil, ftm.err
	}
	return &auth.RefreshTokenPayload{
		UserID: ftm.userID,
	}, nil
}
