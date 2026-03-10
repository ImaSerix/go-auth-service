package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ImaSerix/password-safe-api/internal/dto/auth"
	"github.com/ImaSerix/password-safe-api/internal/service/session"
	"github.com/ImaSerix/password-safe-api/internal/service/user"
	tokenmanager "github.com/ImaSerix/password-safe-api/internal/tokenManager"
)

// TODO Возмобно переименовать SessionSerive.Start метод, он как бы должен обновлять или создавать новую сессию
// TODO Возможные race conditions, хз как их фиксить
// TODO Добавить ошибки на просрочку токенов
// TODO Всё таки добовать Role в accessToken, дабы сэкономить кол-во запросов к базе данных
// TODO Валидацию может быть вынести в метод, имеется ввиду в input типы

type authService struct {
	userSerice     UserService
	sessionService SessionService
	tokenManager   TokenManager
}

func New(us UserService, ss SessionService, tm TokenManager) *authService {
	return &authService{
		userSerice:     us,
		sessionService: ss,
		tokenManager:   tm,
	}
}

type RegisterInput struct {
	Username string
	Password string
	Role     string
}

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

	u, err := as.userSerice.Register(ctx, in.Username, in.Password, in.Role)
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

func (as *authService) Login(ctx context.Context, in *LoginInput) (*auth.UserDTO, *auth.TokenDTO, error) {
	if strings.TrimSpace(in.Username) == "" || len(in.Username) > 32 {
		return nil, nil, ErrInvalidCredentials
	}

	if strings.TrimSpace(in.Password) == "" || len(in.Password) > 256 {
		return nil, nil, ErrInvalidCredentials
	}

	u, err := as.userSerice.ValidateCredentials(ctx, in.Username, in.Password)
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
	user, err := as.userSerice.GetByID(ctx, accPayload.UserID)
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

func (as *authService) Logout(ctx context.Context, in *LogoutInput) error {
	if strings.TrimSpace(in.RefreshToken) == "" {
		return ErrInvalidToken
	}
	refPayload, err := as.tokenManager.ParseRefreshToken(in.RefreshToken)
	if err != nil {
		return ErrInvalidToken
	}
	err = as.sessionService.Revoke(ctx, refPayload.UserID, in.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed revoke session: %w", err)
	}
	return nil
}
