package hasher

import "errors"

var (
	ErrFailedGenerateSalt  = errors.New("failed generate salt")
	ErrInvalidHash         = errors.New("invalid hash")
	ErrUnsuportedAlgorithm = errors.New("unsupported algortihm")
	ErrFailedDecodeString  = errors.New("failed decode string")
	ErrInvalidVersion      = errors.New("invalid version")
	ErrInvalidParams       = errors.New("invalid params")
)
