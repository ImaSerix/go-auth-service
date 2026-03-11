package main

import (
	"log"
	"net/http"

	"github.com/ImaSerix/password-safe-api/internal/config"
	authHandler "github.com/ImaSerix/password-safe-api/internal/handler/auth"
	"github.com/ImaSerix/password-safe-api/internal/hasher/argon2id"
	"github.com/ImaSerix/password-safe-api/internal/repository/postgres"
	"github.com/ImaSerix/password-safe-api/internal/service/session"
	"github.com/ImaSerix/password-safe-api/internal/service/user"
	"github.com/ImaSerix/password-safe-api/internal/storage"
	tokenmanager "github.com/ImaSerix/password-safe-api/internal/tokenManager"
	authService "github.com/ImaSerix/password-safe-api/internal/usecase/auth"
	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Erorr while loading .env file: %v", err)
	}

	cfg := config.Load()

	db, err := storage.NewDBConnection(cfg.DB.FormatDSN())
	if err != nil {
		log.Fatalf("error while connecting to DB: %v", err)
	}

	tm := tokenmanager.NewJWTManager(cfg.JWT.AccessSecret, cfg.JWT.AccessTTL, cfg.JWT.RefreshSecret, cfg.JWT.RefreshTTL)
	hasher := argon2id.New(cfg.Argon2.Memory, cfg.Argon2.Iterations, cfg.Argon2.Parallelism, cfg.Argon2.SaltLength, cfg.Argon2.KeyLength)

	us := user.New(postgres.NewUserRepository(db), hasher)
	ss := session.New(postgres.NewSessionRepository(db), hasher)
	as := authService.New(us, ss, tm)

	ah := authHandler.New(as)

	r := chi.NewRouter()

	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", ah.Register)
		r.Post("/login", ah.Login)
		r.Post("/logout", ah.Logout)
		r.Post("/refresh", ah.Refresh)
		r.Post("/validate", ah.Validate)
	})

	log.Fatal(http.ListenAndServe(":8080", r))
}
