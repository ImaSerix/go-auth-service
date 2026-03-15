package argon2id

// TODO Можно сделать лучше добавив проверку на необходимость перехэшировафать ключ, если какие-то параметры поменялись

import (
	"crypto/rand"
	"fmt"

	"github.com/ImaSerix/password-safe-api/internal/hasher"
	"golang.org/x/crypto/argon2"
)

func (a2h *Argon2Hasher) Hash(password string) (string, error) {
	salt := make([]byte, a2h.saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("%w: %v", hasher.ErrFailedGenerateSalt, err)
	}

	hash := argon2.IDKey([]byte(password), salt, a2h.iterations, a2h.memory, a2h.parallelism, a2h.keyLength)

	params := Argon2Params{
		Version:     argon2.Version,
		Memory:      a2h.memory,
		Iterations:  a2h.iterations,
		Parallelism: a2h.parallelism,
		Salt:        salt,
		Hash:        hash,
	}

	return params.Encode(), nil
}

func (a2h *Argon2Hasher) Verify(password, encoded string) (bool, error) {
	params, err := ParseHash(encoded)
	if err != nil {
		return false, err
	}

	return params.Verify(password), nil
}
