package tokenmanager

import (
	"errors"
	"fmt"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/dto/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTManager struct {
	accessSecret  []byte
	accessTTL     time.Duration
	refreshSecret []byte
	refreshTTL    time.Duration
}

func NewJWTManager(accessSecret []byte, accessTTL time.Duration, refreshSecret []byte, refreshTTL time.Duration) *JWTManager {
	return &JWTManager{
		accessSecret:  accessSecret,
		accessTTL:     accessTTL,
		refreshSecret: refreshSecret,
		refreshTTL:    refreshTTL,
	}
}

func (tm *JWTManager) GenerateAccessToken(userID uuid.UUID) (*auth.AccessTokenDTO, error) {
	now := time.Now()
	expiresAt := now.Add(tm.accessTTL)

	claims := accessClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Issuer:    "auth-service",
			Audience:  []string{"gateway"},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token, err := jwt.
		NewWithClaims(jwt.SigningMethodHS256, claims).
		SignedString(tm.accessSecret)
	if err != nil {
		return nil, fmt.Errorf("tokenManager: %w", err)
	}

	return &auth.AccessTokenDTO{
		AccessToken: token,
		AccessExp:   &expiresAt,
	}, nil
}

func (tm *JWTManager) GenerateRefreshToken(userID uuid.UUID) (*auth.RefreshTokenDTO, error) {
	now := time.Now()
	expiresAt := now.Add(tm.refreshTTL)

	claims := refreshClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Issuer:    "auth-service",
			Audience:  []string{"gateway"},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token, err := jwt.
		NewWithClaims(jwt.SigningMethodHS256, claims).
		SignedString(tm.refreshSecret)
	if err != nil {
		return nil, fmt.Errorf("tokenManager: %w", err)
	}

	return &auth.RefreshTokenDTO{
		RefreshToken: token,
		RefreshExp:   &expiresAt,
	}, nil
}
func (tm *JWTManager) ParseAccessToken(tokenString string) (*auth.AccessTokenPayload, error) {
	token, err := jwt.ParseWithClaims(tokenString, accessClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}

		return tm.accessSecret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(accessClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	return &auth.AccessTokenPayload{
		UserID: claims.UserID,
	}, nil
}
func (tm *JWTManager) ParseRefreshToken(tokenString string) (*auth.RefreshTokenPayload, error) {
	token, err := jwt.ParseWithClaims(tokenString, refreshClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}

		return tm.refreshSecret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(refreshClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	return &auth.RefreshTokenPayload{
		UserID: claims.UserID,
	}, nil
}
