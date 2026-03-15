package argon2id

type Argon2Hasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func New(memory uint32, iterations uint32, parallelism uint8, saltLength uint32, keyLength uint32) *Argon2Hasher {
	return &Argon2Hasher{
		memory,
		iterations,
		parallelism,
		saltLength,
		keyLength,
	}
}
