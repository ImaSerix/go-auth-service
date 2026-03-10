package auth_test

import (
	"errors"
	"testing"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/service/session"
	"github.com/ImaSerix/password-safe-api/internal/service/user"
	tokenmanager "github.com/ImaSerix/password-safe-api/internal/tokenManager"
	"github.com/ImaSerix/password-safe-api/internal/usecase/auth"
	"github.com/google/uuid"
)

func TestRegister_Success(t *testing.T) {
	userService := fakeUserService{
		user: &domain.User{
			ID:           uuid.New(),
			Username:     "username",
			PasswordHash: "some hash",
			Role:         "role",
		},
		called: false,
	}
	sessionService := fakeSessionService{
		called: false,
	}
	tokenManager := fakeTokenManager{
		called: false,
	}

	authService := auth.New(&userService, &sessionService, &tokenManager)

	userDTO, err := authService.Register(t.Context(), &auth.RegisterInput{
		Username: "username",
		Password: "password",
		Role:     "role",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !userService.called {
		t.Fatal("expected user service to be called")
	}
	if userDTO == nil {
		t.Fatal("expected not nil userDTO")
	}
	if sessionService.called {
		t.Fatal("expected session service not to be called")
	}
	if tokenManager.called {
		t.Fatal("expected token manager not to be called")
	}
}

func TestRegister_UsernameTaken(t *testing.T) {
	userService := fakeUserService{
		called: false,
		err:    user.ErrUsernameTaken,
	}
	sessionService := fakeSessionService{
		called: false,
	}
	tokenManager := fakeTokenManager{
		called: false,
	}

	authService := auth.New(&userService, &sessionService, &tokenManager)

	userDTO, err := authService.Register(t.Context(), &auth.RegisterInput{
		Username: "username",
		Password: "password",
		Role:     "role",
	})

	if !errors.Is(err, auth.ErrUsernameTaken) {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !userService.called {
		t.Fatal("expected user service to be called")
	}
	if userDTO != nil {
		t.Fatal("expected nil userDTO")
	}
	if sessionService.called {
		t.Fatal("expected session service not to be called")
	}
	if tokenManager.called {
		t.Fatal("expected token manager not to be called")
	}
}

func TestRegister_IternalError(t *testing.T) {
	userService := fakeUserService{
		called: false,
		err:    errors.New("bad error"),
	}
	sessionService := fakeSessionService{
		called: false,
	}
	tokenManager := fakeTokenManager{
		called: false,
	}

	authService := auth.New(&userService, &sessionService, &tokenManager)

	userDTO, err := authService.Register(t.Context(), &auth.RegisterInput{
		Username: "username",
		Password: "password",
		Role:     "role",
	})

	if err == nil || errors.Is(err, auth.ErrUsernameTaken) {
		t.Fatalf("expected internal error, got %v", err)
	}
	if !userService.called {
		t.Fatal("expected user service to be called")
	}
	if userDTO != nil {
		t.Fatal("expected nil userDTO")
	}
	if sessionService.called {
		t.Fatal("expected session service not to be called")
	}
	if tokenManager.called {
		t.Fatal("expected token manager not to be called")
	}
}

func TestLogin_Success(t *testing.T) {
	userService := fakeUserService{
		user: &domain.User{
			ID:           uuid.New(),
			Username:     "username",
			PasswordHash: "some hash",
			Role:         "role",
		},
		called: false,
	}
	sessionService := fakeSessionService{
		called: false,
	}
	tokenManager := fakeTokenManager{
		called: false,
	}

	authService := auth.New(&userService, &sessionService, &tokenManager)

	userDTO, authDTO, err := authService.Login(t.Context(), &auth.LoginInput{
		Username: "username",
		Password: "password",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !userService.called {
		t.Fatal("expected user service to be called")
	}
	if userDTO == nil {
		t.Fatal("expected not nil userDTO")
	}
	if authDTO == nil {
		t.Fatal("expected not nil authDTO")
	}
	if !sessionService.called {
		t.Fatal("expected session service to be called")
	}
	if !tokenManager.called {
		t.Fatal("expected token manager to be called")
	}
}

func TestLogin_Errors(t *testing.T) {
	tests := []struct {
		name              string
		expErr            error
		internalErr       bool
		userServiceErr    error
		sessionServiceErr error
		tokenManagerErr   error
	}{{
		name:              "invalid credentials",
		expErr:            auth.ErrInvalidCredentials,
		userServiceErr:    user.ErrInvalidCredentials,
		sessionServiceErr: nil,
		tokenManagerErr:   nil,
	}, {
		name:              "user internal error",
		internalErr:       true,
		userServiceErr:    errors.New("internal error"),
		sessionServiceErr: nil,
		tokenManagerErr:   nil,
	}, {
		name:              "auth internal error",
		internalErr:       true,
		userServiceErr:    nil,
		sessionServiceErr: errors.New("internal error"),
		tokenManagerErr:   nil,
	}, {
		name:              "token manager internal error",
		internalErr:       true,
		userServiceErr:    nil,
		sessionServiceErr: nil,
		tokenManagerErr:   errors.New("internal error"),
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userService := fakeUserService{
				user: &domain.User{
					ID:           uuid.New(),
					Username:     "username",
					PasswordHash: "some hash",
					Role:         "role",
				},
				err:    test.userServiceErr,
				called: false,
			}
			sessionService := fakeSessionService{
				err:    test.sessionServiceErr,
				called: false,
			}
			tokenManager := fakeTokenManager{
				err:    test.tokenManagerErr,
				called: false,
			}
			authService := auth.New(&userService, &sessionService, &tokenManager)
			userDTO, authDTO, err := authService.Login(t.Context(), &auth.LoginInput{
				Username: "username",
				Password: "password",
			})

			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !test.internalErr && !errors.Is(err, test.expErr) {
				t.Fatalf("expected %v error, got %v", test.expErr, err)
			}
			if test.internalErr && errors.Is(err, test.expErr) {
				t.Fatalf("expected internal error, got %v", err)
			}
			if userDTO != nil {
				t.Fatal("expected nil userDTO")
			}
			if authDTO != nil {
				t.Fatal("expected nil authDTO")
			}
		})
	}
}

func TestAuthViaToken_Success(t *testing.T) {
	userService := fakeUserService{
		user: &domain.User{
			ID:           uuid.New(),
			Username:     "username",
			PasswordHash: "some hash",
			Role:         "role",
		},
		called: false,
	}
	sessionService := fakeSessionService{
		called: false,
	}
	tokenManager := fakeTokenManager{
		called: false,
	}

	authService := auth.New(&userService, &sessionService, &tokenManager)

	userDTO, err := authService.AuthViaToken(t.Context(), &auth.AuthViaTokenInput{
		AccessToken: "access token",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !userService.called {
		t.Fatal("expected user service to be called")
	}
	if userDTO == nil {
		t.Fatal("expected not nil userDTO")
	}
	if !tokenManager.called {
		t.Fatal("expected token manager to be called")
	}
	if sessionService.called {
		t.Fatal("expected session service not to be called")
	}
}

func TestAuthViaToken_Errors(t *testing.T) {
	tests := []struct {
		name              string
		expErr            error
		internalErr       bool
		userServiceErr    error
		sessionServiceErr error
		tokenManagerErr   error
	}{{
		name:              "invalid token",
		expErr:            auth.ErrInvalidToken,
		userServiceErr:    nil,
		sessionServiceErr: nil,
		tokenManagerErr:   tokenmanager.ErrInvalidToken,
	}, {
		name:              "token expired",
		expErr:            auth.ErrTokenExpired,
		userServiceErr:    nil,
		sessionServiceErr: nil,
		tokenManagerErr:   tokenmanager.ErrTokenExpired,
	}, {
		name:              "user internal error",
		internalErr:       true,
		userServiceErr:    errors.New("internal error"),
		sessionServiceErr: nil,
		tokenManagerErr:   nil,
	}, {
		name:              "token manager internal error",
		internalErr:       true,
		userServiceErr:    nil,
		sessionServiceErr: nil,
		tokenManagerErr:   errors.New("internal error"),
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userService := fakeUserService{
				user: &domain.User{
					ID:           uuid.New(),
					Username:     "username",
					PasswordHash: "some hash",
					Role:         "role",
				},
				err:    test.userServiceErr,
				called: false,
			}
			sessionService := fakeSessionService{
				err:    test.sessionServiceErr,
				called: false,
			}
			tokenManager := fakeTokenManager{
				err:    test.tokenManagerErr,
				called: false,
			}
			authService := auth.New(&userService, &sessionService, &tokenManager)
			userDTO, err := authService.AuthViaToken(t.Context(), &auth.AuthViaTokenInput{
				AccessToken: "access token",
			})

			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !test.internalErr && !errors.Is(err, test.expErr) {
				t.Fatalf("expected %v error, got %v", test.expErr, err)
			}
			if test.internalErr && errors.Is(err, test.expErr) {
				t.Fatalf("expected internal error, got %v", err)
			}
			if userDTO != nil {
				t.Fatal("expected nil userDTO")
			}
		})
	}
}

func TestRefresh_Success(t *testing.T) {
	userService := fakeUserService{
		user: &domain.User{
			ID:           uuid.New(),
			Username:     "username",
			PasswordHash: "some hash",
			Role:         "role",
		},
		called: false,
	}
	sessionService := fakeSessionService{
		called: false,
	}
	tokenManager := fakeTokenManager{
		called: false,
	}

	authService := auth.New(&userService, &sessionService, &tokenManager)

	tokenDTO, err := authService.Refresh(t.Context(), &auth.RefreshInput{
		RefreshToken: "refresh token",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !sessionService.called {
		t.Fatal("expected session service to be called")
	}
	if tokenDTO == nil {
		t.Fatal("expected not nil tokenDTO")
	}
	if !tokenManager.called {
		t.Fatal("expected token manager to be called")
	}
}

func TestRefresh_Errors(t *testing.T) {
	tests := []struct {
		name              string
		expErr            error
		internalErr       bool
		userServiceErr    error
		sessionServiceErr error
		tokenManagerErr   error
	}{{
		name:              "invalid token",
		expErr:            auth.ErrInvalidToken,
		userServiceErr:    nil,
		sessionServiceErr: nil,
		tokenManagerErr:   tokenmanager.ErrInvalidToken,
	}, {
		name:              "token expired",
		expErr:            auth.ErrTokenExpired,
		userServiceErr:    nil,
		sessionServiceErr: nil,
		tokenManagerErr:   tokenmanager.ErrTokenExpired,
	}, {
		name:              "token reuse",
		expErr:            auth.ErrTokenReuse,
		userServiceErr:    nil,
		sessionServiceErr: session.ErrTokenMismatch,
		tokenManagerErr:   nil,
	}, {
		name:              "session internal error",
		internalErr:       true,
		userServiceErr:    nil,
		sessionServiceErr: errors.New("internal error"),
		tokenManagerErr:   nil,
	}, {
		name:              "token manager internal error",
		internalErr:       true,
		userServiceErr:    nil,
		sessionServiceErr: nil,
		tokenManagerErr:   errors.New("internal error"),
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userService := fakeUserService{
				user: &domain.User{
					ID:           uuid.New(),
					Username:     "username",
					PasswordHash: "some hash",
					Role:         "role",
				},
				err:    test.userServiceErr,
				called: false,
			}
			sessionService := fakeSessionService{
				err:    test.sessionServiceErr,
				called: false,
			}
			tokenManager := fakeTokenManager{
				err:    test.tokenManagerErr,
				called: false,
			}
			authService := auth.New(&userService, &sessionService, &tokenManager)
			tokenDTO, err := authService.Refresh(t.Context(), &auth.RefreshInput{
				RefreshToken: "access token",
			})

			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !test.internalErr && !errors.Is(err, test.expErr) {
				t.Fatalf("expected %v error, got %v", test.expErr, err)
			}
			if test.internalErr && errors.Is(err, test.expErr) {
				t.Fatalf("expected internal error, got %v", err)
			}
			if tokenDTO != nil {
				t.Fatal("expected nil tokenDTO")
			}
		})
	}
}

func TestLogout_Success(t *testing.T) {
	userService := fakeUserService{
		user: &domain.User{
			ID:           uuid.New(),
			Username:     "username",
			PasswordHash: "some hash",
			Role:         "role",
		},
		called: false,
	}
	sessionService := fakeSessionService{
		called: false,
	}
	tokenManager := fakeTokenManager{
		called: false,
	}

	authService := auth.New(&userService, &sessionService, &tokenManager)

	err := authService.Logout(t.Context(), &auth.LogoutInput{
		RefreshToken: "refresh token",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !sessionService.called {
		t.Fatal("expected session service to be called")
	}
	if !tokenManager.called {
		t.Fatal("expected token manager to be called")
	}
}

func TestLogout_Errors(t *testing.T) {
	tests := []struct {
		name              string
		expErr            error
		internalErr       bool
		userServiceErr    error
		sessionServiceErr error
		tokenManagerErr   error
	}{{
		name:              "invalid token",
		expErr:            auth.ErrInvalidToken,
		userServiceErr:    nil,
		sessionServiceErr: nil,
		tokenManagerErr:   tokenmanager.ErrInvalidToken,
	}, {
		name:              "session internal error",
		internalErr:       true,
		userServiceErr:    nil,
		sessionServiceErr: errors.New("internal error"),
		tokenManagerErr:   nil,
	}, {
		name:              "token manager internal error",
		internalErr:       true,
		userServiceErr:    nil,
		sessionServiceErr: nil,
		tokenManagerErr:   errors.New("internal error"),
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userService := fakeUserService{
				user: &domain.User{
					ID:           uuid.New(),
					Username:     "username",
					PasswordHash: "some hash",
					Role:         "role",
				},
				err:    test.userServiceErr,
				called: false,
			}
			sessionService := fakeSessionService{
				err:    test.sessionServiceErr,
				called: false,
			}
			tokenManager := fakeTokenManager{
				err:    test.tokenManagerErr,
				called: false,
			}
			authService := auth.New(&userService, &sessionService, &tokenManager)
			err := authService.Logout(t.Context(), &auth.LogoutInput{
				RefreshToken: "access token",
			})

			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !test.internalErr && !errors.Is(err, test.expErr) {
				t.Fatalf("expected %v error, got %v", test.expErr, err)
			}
			if test.internalErr && errors.Is(err, test.expErr) {
				t.Fatalf("expected internal error, got %v", err)
			}
		})
	}
}
