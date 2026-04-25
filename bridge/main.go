package main

import (
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/ic4y/cyphrmask-oidc-poc/bridge/handlers"
	"github.com/ic4y/cyphrmask-oidc-poc/bridge/storage"
)

//go:embed templates/*
var templateFS embed.FS

func main() {
	cfg := loadConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelInfo,
	}))

	oidcStore := storage.NewStorage()
	oidcStore.RegisterClient(storage.NewClient(cfg.ClientID, cfg.ClientSecret, []string{cfg.CallbackURL}, func(id string) string {
		return "/login?authRequestID=" + id
	}))

	challengeStore := handlers.NewChallengeStore(time.Minute * 5)

	key := sha256.Sum256([]byte(cfg.ClientSecret))
	provider, err := op.NewOpenIDProvider(cfg.IssuerURL, &op.Config{
		CryptoKey:                key,
		DefaultLogoutRedirectURI: cfg.CallbackURL,
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  false,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   false,
		SupportedUILocales:       nil,
	}, oidcStore, op.WithAllowInsecure(), op.WithLogger(logger.WithGroup("oidc")))
	if err != nil {
		log.Fatalf("failed to create OIDC provider: %v", err)
	}

	tmpl, err := template.ParseFS(templateFS, "templates/*")
	if err != nil {
		log.Fatalf("failed to parse templates: %v", err)
	}

	loginHandler := handlers.NewLoginHandler(oidcStore, tmpl, cfg.IssuerURL)

	router := chi.NewRouter()
	router.Use(logging.Middleware(logging.WithLogger(logger)))

	router.Mount("/", http.Handler(provider))
	router.Handle("/login", loginHandler)
	router.HandleFunc("/login/callback", op.AuthorizeCallbackHandler(provider))
	router.HandleFunc("GET /api/challenge", handlers.HandleChallenge(challengeStore))
	router.HandleFunc("POST /api/verify", handlers.HandleVerify(challengeStore, oidcStore))
	router.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("Cyphr-OIDC Bridge listening on %s", addr)
	log.Printf("Issuer URL: %s", cfg.IssuerURL)
	log.Printf("Client ID: %s", cfg.ClientID)
	log.Printf("Discovery: %s/.well-known/openid-configuration", cfg.IssuerURL)

	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

type Config struct {
	Port         string
	IssuerURL    string
	ClientID     string
	ClientSecret string
	CallbackURL  string
}

func loadConfig() Config {
	return Config{
		Port:         getEnv("BRIDGE_PORT", "8080"),
		IssuerURL:    getEnv("BRIDGE_ISSUER_URL", "http://localhost:8080"),
		ClientID:     getEnv("BRIDGE_CLIENT_ID", "cyphrmask-poc"),
		ClientSecret: getEnv("BRIDGE_CLIENT_SECRET", "dev-secret-change-me"),
		CallbackURL:  getEnv("BRIDGE_CALLBACK_URL", "http://localhost:8080/callback"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
