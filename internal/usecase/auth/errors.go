package auth

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidUsername    = errors.New("invalid username")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrInvalidRole        = errors.New("invalid role")
	ErrUsernameTaken      = errors.New("username taken")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenReuse         = errors.New("token reuse")
)
