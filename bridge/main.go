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

	oidcStore := storage.NewStorageWithKeyPath(cfg.SigningKeyPath)
	registerClients(oidcStore, cfg)

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
	// Allow requests from extension origins (chrome-extension://) and local origins
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	router.Mount("/", http.Handler(provider))
	router.Handle("/login", loginHandler)
	router.Handle("/login/callback", handlers.NewCallbackHandler(oidcStore))
	router.Handle("/callback", handlers.NewTokenCallbackHandler(oidcStore))
	router.HandleFunc("GET /api/challenge", handlers.HandleChallenge(challengeStore))
	router.HandleFunc("POST /api/verify", handlers.HandleVerify(challengeStore, oidcStore, cfg.Users))
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

type ClientConfig struct {
	ID           string   `json:"id"`
	Secret       string   `json:"secret"`
	RedirectURIs []string `json:"redirect_uris"`
}

type Config struct {
	Port           string
	IssuerURL      string
	ClientID       string
	ClientSecret   string
	CallbackURL    string
	SigningKeyPath string
	Users          string
	Clients        string
}

func loadConfig() Config {
	return Config{
		Port:           getEnv("BRIDGE_PORT", "8080"),
		IssuerURL:      getEnv("BRIDGE_ISSUER_URL", "http://localhost:8080"),
		ClientID:       getEnv("BRIDGE_CLIENT_ID", "cyphrmask-poc"),
		ClientSecret:   getEnv("BRIDGE_CLIENT_SECRET", "dev-secret-change-me"),
		CallbackURL:    getEnv("BRIDGE_CALLBACK_URL", "http://localhost:8080/callback"),
		SigningKeyPath: getEnv("BRIDGE_SIGNING_KEY_PATH", ""),
		Users:          getEnv("BRIDGE_USERS", ""),
		Clients:        getEnv("BRIDGE_CLIENTS", ""),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func registerClients(store *storage.Storage, cfg Config) {
	loginURL := func(id string) string {
		return "/login?authRequestID=" + id
	}

	if cfg.Clients != "" {
		var clients []ClientConfig
		if err := json.Unmarshal([]byte(cfg.Clients), &clients); err != nil {
			log.Fatalf("failed to parse BRIDGE_CLIENTS: %v", err)
		}
		for _, c := range clients {
			store.RegisterClient(storage.NewClient(c.ID, c.Secret, c.RedirectURIs, loginURL))
			log.Printf("registered client: %s (redirect URIs: %v)", c.ID, c.RedirectURIs)
		}
		return
	}

	// Default: register the single client from env vars
	store.RegisterClient(storage.NewClient(cfg.ClientID, cfg.ClientSecret, []string{cfg.CallbackURL}, loginURL))
	log.Printf("registered default client: %s", cfg.ClientID)
}
