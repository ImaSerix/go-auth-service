package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dto "github.com/ImaSerix/password-safe-api/internal/dto/auth"
	"github.com/ImaSerix/password-safe-api/internal/usecase/auth"
	"github.com/google/uuid"
)

type fakeAuthService struct {
	auth.AuthService
	user   *dto.UserDTO
	err    error
	called bool
	token  string
}

func (f *fakeAuthService) AuthViaToken(ctx context.Context, in *auth.AuthViaTokenInput) (*dto.UserDTO, error) {
	f.called = true
	f.token = in.AccessToken
	if f.err != nil {
		return nil, f.err
	}
	return f.user, nil
}

func TestValidate_TokenFromAuthorizationHeader(t *testing.T) {
	user := &dto.UserDTO{ID: uuid.New(), Username: "alice", Role: "user"}
	as := &fakeAuthService{user: user}

	// The body holds another token: it must be ignored.
	r := httptest.NewRequest(http.MethodPost, "/auth/validate", strings.NewReader(`{"accessToken":"from-body"}`))
	r.Header.Set("Authorization", "Bearer from-header")
	w := httptest.NewRecorder()

	New(as).Validate(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if as.token != "from-header" {
		t.Fatalf("token = %q, want %q", as.token, "from-header")
	}

	var resp ValidateResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ID != user.ID || resp.Username != user.Username || len(resp.Roles) != 1 || resp.Roles[0] != user.Role {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestValidate_NoBody(t *testing.T) {
	as := &fakeAuthService{user: &dto.UserDTO{ID: uuid.New()}}

	r := httptest.NewRequest(http.MethodPost, "/auth/validate", nil)
	r.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()

	New(as).Validate(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestValidate_BadAuthorizationHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{name: "no header", header: ""},
		{name: "no scheme", header: "token"},
		{name: "other scheme", header: "Basic token"},
		{name: "scheme without space", header: "Bearer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := &fakeAuthService{}

			// A token in the body alone is not accepted any more.
			r := httptest.NewRequest(http.MethodPost, "/auth/validate", strings.NewReader(`{"accessToken":"from-body"}`))
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}
			w := httptest.NewRecorder()

			New(as).Validate(w, r)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
			}
			if as.called {
				t.Fatal("AuthViaToken must not be called")
			}
		})
	}
}

func TestValidate_ServiceErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code int
	}{
		{name: "invalid token", err: auth.ErrInvalidToken, code: http.StatusUnauthorized},
		{name: "token expired", err: auth.ErrTokenExpired, code: http.StatusUnauthorized},
		{name: "internal error", err: context.DeadlineExceeded, code: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := &fakeAuthService{err: tt.err}

			r := httptest.NewRequest(http.MethodPost, "/auth/validate", nil)
			r.Header.Set("Authorization", "Bearer token")
			w := httptest.NewRecorder()

			New(as).Validate(w, r)

			if w.Code != tt.code {
				t.Fatalf("status = %d, want %d", w.Code, tt.code)
			}
		})
	}
}
