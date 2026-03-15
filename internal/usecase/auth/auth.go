package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ImaSerix/password-safe-api/internal/dto/auth"
	"github.com/ImaSerix/password-safe-api/internal/service/session"
	"github.com/ImaSerix/password-safe-api/internal/service/user"
	"github.com/ImaSerix/password-safe-api/internal/tokenmanager"
)

type authService struct {
	userService    UserService
	sessionService SessionService
	tokenManager   TokenManager
}

func New(us UserService, ss SessionService, tm TokenManager) *authService {
	return &authService{
		userService:    us,
		sessionService: ss,
		tokenManager:   tm,
	}
}

type RegisterInput struct {
	Username string
	Password string
	Role     string
}

// Register validates registration input, delegates creation to the user service,
// and returns a user DTO.
// Returns ErrInvalidUsername, ErrInvalidPassword, ErrInvalidRole on validation
// errors and ErrUsernameTaken when the username is already used.
func (as *authService) Register(ctx context.Context, in *RegisterInput) (*auth.UserDTO, error) {
	if strings.TrimSpace(in.Username) == "" || len(in.Username) > 32 || len(in.Username) < 4 {
		return nil, ErrInvalidUsername
	}

	if strings.TrimSpace(in.Password) == "" || len(in.Password) > 256 || len(in.Password) < 8 {
		return nil, ErrInvalidPassword
	}

	if strings.TrimSpace(in.Role) == "" || len(in.Role) > 32 || len(in.Role) < 2 {
		return nil, ErrInvalidRole
	}

	u, err := as.userService.Register(ctx, in.Username, in.Password, in.Role)
	if err != nil {
		if errors.Is(err, user.ErrUsernameTaken) {
			return nil, ErrUsernameTaken
		}
		return nil, fmt.Errorf("register user failed: %w", err)
	}

	return &auth.UserDTO{
		ID:       u.ID,
		Username: u.Username,
		Role:     u.Role,
	}, nil
}

type LoginInput struct {
	Username string
	Password string
}

// Login validates credentials, issues access/refresh tokens, and starts (or
// updates) a user session.
//
// Purpose:
//   - Implements initial authentication and returns a token pair.
//
// Input:
//   - ctx: context for cancellation/deadline.
//   - in: input object with fields:
//   - Username: non-empty string, max 32 characters.
//   - Password: non-empty string, max 256 characters.
//
// Output:
//   - On success returns user DTO and token DTO.
//   - On error returns nil values and an error.
//
// Errors:
//   - ErrInvalidCredentials: returned for obviously invalid input or failed
//     credential validation from the user service.
//
// Side effects:
//   - Generates tokens.
//   - Writes/updates session data in storage.
func (as *authService) Login(ctx context.Context, in *LoginInput) (*auth.UserDTO, *auth.TokenDTO, error) {
	if strings.TrimSpace(in.Username) == "" || len(in.Username) > 32 {
		return nil, nil, ErrInvalidCredentials
	}

	if strings.TrimSpace(in.Password) == "" || len(in.Password) > 256 {
		return nil, nil, ErrInvalidCredentials
	}

	u, err := as.userService.ValidateCredentials(ctx, in.Username, in.Password)
	if err != nil {
		if errors.Is(err, user.ErrInvalidCredentials) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, fmt.Errorf("failed validate credentials: %w", err)
	}
	refPayload, err := as.tokenManager.GenerateRefreshToken(u.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed generate refresh token: %w", err)
	}
	err = as.sessionService.Start(ctx, u.ID, refPayload.RefreshToken, refPayload.RefreshExp)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start session: %w", err)
	}
	accPayload, err := as.tokenManager.GenerateAccessToken(u.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate token : %w", err)
	}
	return &auth.UserDTO{
			ID:       u.ID,
			Username: u.Username,
			Role:     u.Role,
		}, &auth.TokenDTO{
			AccessToken:  accPayload.AccessToken,
			AccessExp:    accPayload.AccessExp,
			RefreshToken: refPayload.RefreshToken,
			RefreshExp:   refPayload.RefreshExp,
		}, nil
}

type AuthViaTokenInput struct {
	AccessToken string
}

// AuthViaToken validates an access token and returns the corresponding user DTO.
//
// Purpose:
//   - Supports token-based re-authentication.
//
// Input:
//   - ctx: context for cancellation/deadline.
//   - in: input object with field:
//   - AccessToken: JWT string.
//
// Output:
//   - On success returns user DTO.
//   - On error returns nil and an error.
//
// Errors:
//   - ErrInvalidToken: malformed token or invalid signature.
//   - ErrTokenExpired: token is expired.
func (as *authService) AuthViaToken(ctx context.Context, in *AuthViaTokenInput) (*auth.UserDTO, error) {
	if strings.TrimSpace(in.AccessToken) == "" {
		return nil, ErrInvalidToken
	}
	accPayload, err := as.tokenManager.ParseAccessToken(in.AccessToken)
	if err != nil {
		if errors.Is(err, tokenmanager.ErrInvalidToken) {
			return nil, ErrInvalidToken
		}
		if errors.Is(err, tokenmanager.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("failed parse token: %w", err)
	}
	user, err := as.userService.GetByID(ctx, accPayload.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed find user %s: %w", accPayload.UserID, err)
	}
	return &auth.UserDTO{
		ID:       user.ID,
		Username: user.Username,
		Role:     user.Role,
	}, nil
}

type RefreshInput struct {
	RefreshToken string
}

// Refresh validates a refresh token, rotates the session token, and returns a
// new access/refresh pair.
//
// Purpose:
//   - Allows clients to continue authentication flow without username/password.
//
// Input:
//   - ctx: context for cancellation/deadline.
//   - in: input object with field:
//   - RefreshToken: JWT string.
//
// Output:
//   - On success returns token DTO.
//   - On error returns nil and an error.
//
// Errors:
//   - ErrInvalidToken: malformed token or invalid signature.
//   - ErrTokenExpired: token is expired.
//   - ErrTokenReuse: revoked/rotated refresh token was reused.
//
// Side effects:
//   - Generates a new access/refresh pair.
//   - Rotates refresh token data in session storage.
func (as *authService) Refresh(ctx context.Context, in *RefreshInput) (*auth.TokenDTO, error) {
	if strings.TrimSpace(in.RefreshToken) == "" {
		return nil, ErrInvalidToken
	}
	refPayload, err := as.tokenManager.ParseRefreshToken(in.RefreshToken)
	if err != nil {
		if errors.Is(err, tokenmanager.ErrInvalidToken) {
			return nil, ErrInvalidToken
		}
		if errors.Is(err, tokenmanager.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("failed parse token: %w", err)
	}
	refreshDTO, err := as.tokenManager.GenerateRefreshToken(refPayload.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed generate refresh token: %w", err)
	}
	err = as.sessionService.Rotate(ctx, refPayload.UserID, in.RefreshToken, refreshDTO.RefreshToken, refreshDTO.RefreshExp)
	if err != nil {
		if errors.Is(err, session.ErrTokenMismatch) {
			return nil, ErrTokenReuse
		}
		return nil, fmt.Errorf("failed rotate refresh token: %w", err)
	}
	accessDTO, err := as.tokenManager.GenerateAccessToken(refPayload.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed generate access token: %w", err)
	}
	return &auth.TokenDTO{
		AccessToken:  accessDTO.AccessToken,
		RefreshToken: refreshDTO.RefreshToken,
		AccessExp:    accessDTO.AccessExp,
		RefreshExp:   refreshDTO.RefreshExp,
	}, nil
}

type LogoutInput struct {
	RefreshToken string
}

// Logout validates a refresh token and revokes the corresponding user session.
// Returns ErrInvalidToken for malformed token/signature issues and
// ErrTokenExpired when the token is expired.
func (as *authService) Logout(ctx context.Context, in *LogoutInput) error {
	if strings.TrimSpace(in.RefreshToken) == "" {
		return ErrInvalidToken
	}
	refPayload, err := as.tokenManager.ParseRefreshToken(in.RefreshToken)
	if err != nil {
		if errors.Is(err, tokenmanager.ErrInvalidToken) {
			return ErrInvalidToken
		}
		if errors.Is(err, tokenmanager.ErrTokenExpired) {
			return ErrTokenExpired
		}
		return fmt.Errorf("failed parse refresh token %w", err)
	}
	err = as.sessionService.Revoke(ctx, refPayload.UserID, in.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed revoke session: %w", err)
	}
	return nil
}
