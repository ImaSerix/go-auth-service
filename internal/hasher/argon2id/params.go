package argon2id

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/ImaSerix/password-safe-api/internal/hasher"
	"golang.org/x/crypto/argon2"
)

type Argon2Params struct {
	Version     int
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	Salt        []byte
	Hash        []byte
}

func (a2p *Argon2Params) Encode() string {
	b64Salt := base64.RawStdEncoding.EncodeToString(a2p.Salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(a2p.Hash)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		a2p.Version,
		a2p.Memory,
		a2p.Iterations,
		a2p.Parallelism,
		b64Salt,
		b64Hash,
	)
}

func ParseHash(encoded string) (*Argon2Params, error) {
	params := Argon2Params{}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return nil, hasher.ErrInvalidHash
	}

	if parts[1] != "argon2id" {
		return nil, hasher.ErrUnsuportedAlgorithm
	}

	versionPart := parts[2]
	_, err := fmt.Sscanf(versionPart, "v=%d", &params.Version)
	if err != nil {
		return nil, hasher.ErrInvalidVersion
	}

	if params.Version != argon2.Version {
		return nil, hasher.ErrInvalidVersion
	}

	paramPart := strings.Split(parts[3], ",")

	for _, p := range paramPart {
		if strings.HasPrefix(p, "m=") {
			if _, err := fmt.Sscanf(p, "m=%d", &params.Memory); err != nil {
				return nil, hasher.ErrInvalidParams
			}
		}
		if strings.HasPrefix(p, "t=") {
			if _, err := fmt.Sscanf(p, "t=%d", &params.Iterations); err != nil {
				return nil, hasher.ErrInvalidParams
			}
		}
		if strings.HasPrefix(p, "p=") {
			if _, err := fmt.Sscanf(p, "p=%d", &params.Parallelism); err != nil {
				return nil, hasher.ErrInvalidParams
			}
		}
	}

	if params.Memory == 0 || params.Iterations == 0 || params.Parallelism == 0 {
		return nil, hasher.ErrInvalidParams
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("failed decode string: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("failed decode string: %w", err)
	}

	if len(salt) == 0 || len(hash) == 0 {
		return nil, hasher.ErrInvalidHash
	}

	params.Salt = salt
	params.Hash = hash

	return &params, nil
}

func (a2p *Argon2Params) Verify(password string) bool {
	newHash := argon2.IDKey(
		[]byte(password),
		a2p.Salt,
		a2p.Iterations,
		a2p.Memory,
		a2p.Parallelism,
		uint32(len(a2p.Hash)),
	)

	return subtle.ConstantTimeCompare(newHash, a2p.Hash) == 1
}
