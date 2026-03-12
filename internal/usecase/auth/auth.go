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

// Register стандартная функция регистрации, валидирует данные и передаёт их сервису пользователей, возвращает DTO пользователя.
// Returns ErrInvalidUsername, ErrInvalidPassword, ErrInvalidRole при ошибках валидации и ErrUsernameTaken, если имя пользователя занято.
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

// Login валидирует реквизиты для входа, при успехе генерирует токены доступа и обновления, а также создаёт/обновляет сессию пользователя.
//
// Purpose:
//   - Реализует первичную авторизацию, предоставляя токены для входа и обновления
//
// Input:
//   - ctx: для отмены/дедлайна
//   - in: структура с полями
//     Username: не пустая строка, имеющая не более 32 символа
//     Password: не пистая строка, имеющая не более 256 символов
//
// Output:
//   - При успехе возвращает DTO пользователя и DTO токенов
//   - При ошибке возвращаются nil и ошибка
//
// Errors:
//   - ErrInvalidCredentials: возникает при вводе заведомо невалидных реквизитов или при негативной валидации от сервиса пользователя
//
// Side effects:
//   - Генерирует токены
//   - Записывает/обновляет сессию в БД
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

// AuthViaToken парсит токен входа, при успехе возвращает соответсвующий токену DTO пользователя.
//
// Purpose:
//   - Позволяет валидировать токены входа, тем самым реализуя повторную аутентификацию через токены.
//
// Input:
//   - ctx: для отмены/дедлайна.
//   - in: структура с полем
//     AccessToken: валидная JWT строка
//
// Output:
//   - При успехе возвращается DTO пользователя.
//   - При ошибки возвращается nil и ошибка.
//
// Errors:
//   - ErrInvalidToken: возникает при дефектном токене или при негодной подписи.
//   - ErrTokenExpired: возникает, если токен просрочен.
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

// Refresh парсит токен обновления, при успехе генерирует новый токены доступа и обновления, обновляет данные в сессии.
//
// Purpose:
//   - Позволяет обновлять просроченный токен входа используя токен обновления.
//
// Input:
//   - ctx: для отмены/дедлайна.
//   - in: структура с полем
//     RefreshToken: валидная JWT строка
//
// Output:
//   - При успехе возвращается DTO токенов.
//   - При ошибки возвращается nil и ошибка.
//
// Errors:
//   - ErrInvalidToken: возникает при дефектном токене или при негодной подписи.
//   - ErrTokenExpired: возникает, если токен просрочен.
//   - ErrTokenReuse: возникает при константации использования отозванного токена обновления.
//
// Side effects:
//   - Генерирует новые токены входа и обновления
//   - Производит ротацию токена обновления в сессии
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

// Logout парсит токен обновления, при успехе отзывает сессию пользователя, тем самым не позволяя обновлять токены.
// Returns ErrInvalidToken при дефектном токене или при невалидной подписи, ErrTokenExpired при просрочке токена.
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
