package config

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"time"
)

type Config struct {
	DB     DBConfig
	JWT    JWTConfig
	Argon2 Argon2Config
}

type DBConfig struct {
	Host     string
	Port     int
	Name     string
	User     string
	Password string
	SSLMode  string
}

func (c DBConfig) FormatDSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		url.QueryEscape(c.User),
		url.QueryEscape(c.Password),
		c.Host,
		c.Port,
		c.Name,
		c.SSLMode,
	)
}

type JWTConfig struct {
	AccessSecret  []byte
	AccessTTL     time.Duration
	RefreshSecret []byte
	RefreshTTL    time.Duration
}

type Argon2Config struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing env %s", key)
	}
	return v
}

func Load() *Config {

	port, err := strconv.Atoi(mustEnv("DB_PORT"))
	if err != nil {
		log.Printf("invalid DB_PORT, fallback to 5432: %v", err)
		port = 5432
	}

	accessTTL, err := time.ParseDuration(mustEnv("JWT_ACCESS_TTL"))
	if err != nil {
		log.Printf("invalid accessTTL, fallback to 15 minute: %v", err)
		accessTTL = time.Duration(15 * time.Minute)
	}

	refreshTTL, err := time.ParseDuration(mustEnv("JWT_REFRESH_TTL"))
	if err != nil {
		log.Printf("invalid refreshTTL, fallback to 720 hour: %v", err)
		refreshTTL = time.Duration(720 * time.Hour)
	}

	memory, err := strconv.ParseUint(mustEnv("ARGON2_MEMORY"), 10, 32)
	if err != nil {
		log.Printf("invalid argon memory, fallback to 65536: %v", err)
		memory = 65536
	}
	iterations, err := strconv.ParseUint(mustEnv("ARGON2_ITERATIONS"), 10, 32)
	if err != nil {
		log.Printf("invalid argon iterations, fallback to 3: %v", err)
		iterations = 3
	}
	parallelism, err := strconv.ParseUint(mustEnv("ARGON2_PARALLELISM"), 10, 8)
	if err != nil {
		log.Printf("invalid argon parallelism, fallback to 3: %v", err)
		parallelism = 2
	}
	saltLength, err := strconv.ParseUint(mustEnv("ARGON2_SALT_LENGTH"), 10, 32)
	if err != nil {
		log.Printf("invalid argon saltLength, fallback to 16: %v", err)
		saltLength = 16
	}
	keyLength, err := strconv.ParseUint(mustEnv("ARGON2_KEY_LENGTH"), 10, 32)
	if err != nil {
		log.Printf("invalid argon keyLenght, fallback to 32: %v", err)
		keyLength = 32
	}

	return &Config{
		DB: DBConfig{
			Host:     mustEnv("DB_HOST"),
			Port:     port,
			Name:     mustEnv("DB_NAME"),
			User:     mustEnv("DB_USER"),
			Password: os.Getenv("DB_PASSWORD"),
			SSLMode:  mustEnv("DB_SSLMODE"),
		},
		JWT: JWTConfig{
			AccessSecret:  []byte(mustEnv("JWT_ACCESS_SECRET")),
			AccessTTL:     accessTTL,
			RefreshSecret: []byte(mustEnv("JWT_REFRESH_SECRET")),
			RefreshTTL:    refreshTTL,
		},
		Argon2: Argon2Config{
			Memory:      uint32(memory),
			Iterations:  uint32(iterations),
			Parallelism: uint8(parallelism),
			SaltLength:  uint32(saltLength),
			KeyLength:   uint32(keyLength),
		},
	}
}
