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
	DB  DBConfig
	JWT JWTConfig
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
	AccessSecret []byte
	AccessTTL    time.Duration
	RefreshKey   []byte
	RefreshTTL   time.Time
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
			AccessSecret: []byte(mustEnv("")),
		},
	}
}
