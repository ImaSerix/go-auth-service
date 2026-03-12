package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ImaSerix/password-safe-api/internal/usecase/auth"
)

type AuthHandler struct {
	as auth.AuthService
}

func New(as auth.AuthService) *AuthHandler {
	return &AuthHandler{
		as: as,
	}
}

func (ah *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		logError(r, err)

		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	in := auth.RegisterInput{
		Username: req.Username,
		Password: req.Password,
		Role:     req.Role,
	}

	user, err := ah.as.Register(r.Context(), &in)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidUsername), errors.Is(err, auth.ErrInvalidPassword), errors.Is(err, auth.ErrInvalidRole):
			http.Error(w, "invalid credentials", http.StatusBadRequest)
			return
		case errors.Is(err, auth.ErrUsernameTaken):
			http.Error(w, "username taken", http.StatusConflict)
			return
		default:
			logError(r, err)

			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

	}

	resp := RegisterResponse{
		ID: user.ID,
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (ah *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		logError(r, err)

		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	in := auth.LoginInput{
		Username: req.Username,
		Password: req.Password,
	}

	user, tokens, err := ah.as.Login(r.Context(), &in)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		default:
			logError(r, err)

			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	resp := LoginResponse{
		ID:           user.ID,
		AccessToken:  tokens.AccessToken,
		AccessExp:    *tokens.AccessExp,
		RefreshToken: tokens.RefreshToken,
		RefreshExp:   *tokens.RefreshExp,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (ah *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req LogoutRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		logError(r, err)

		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	in := auth.LogoutInput{
		RefreshToken: req.RefreshToken,
	}

	err := ah.as.Logout(r.Context(), &in)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidToken):
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		case errors.Is(err, auth.ErrTokenExpired):
			http.Error(w, "token expired", http.StatusUnauthorized)
			return
		default:
			logError(r, err)

			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

	}

	resp := LogoutResponse{
		Status: "logged out",
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (ah *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		logError(r, err)

		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	in := auth.RefreshInput{
		RefreshToken: req.RefreshToken,
	}

	tokens, err := ah.as.Refresh(r.Context(), &in)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidToken):
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		case errors.Is(err, auth.ErrTokenExpired):
			http.Error(w, "token expired", http.StatusUnauthorized)
			return
		case errors.Is(err, auth.ErrTokenReuse):
			http.Error(w, "token reuse", http.StatusUnauthorized)
			return
		default:
			logError(r, err)

			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	resp := RefreshResponse{
		AccessToken:  tokens.AccessToken,
		AccessExp:    *tokens.AccessExp,
		RefreshToken: tokens.RefreshToken,
		RefreshExp:   *tokens.RefreshExp,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (ah *AuthHandler) Validate(w http.ResponseWriter, r *http.Request) {
	var req ValidateRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		logError(r, err)

		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	in := auth.AuthViaTokenInput{
		AccessToken: req.AccessToken,
	}

	user, err := ah.as.AuthViaToken(r.Context(), &in)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidToken):
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		case errors.Is(err, auth.ErrTokenExpired):
			http.Error(w, "token expired", http.StatusUnauthorized)
			return
		default:
			logError(r, err)

			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	resp := ValidateResponse{
		ID:       user.ID,
		Username: user.Username,
		Roles:    []string{user.Role},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
