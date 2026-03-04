package repository

import "errors"

var (
	ErrNotFound       = errors.New("not found")
	ErrAlreadyExists  = errors.New("already exists")
	ErrInvalidRefresh = errors.New("invalid refresh")
)
