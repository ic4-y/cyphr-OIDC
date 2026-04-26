package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/ic4y/cyphrmask-oidc-poc/bridge/crypto"
	"github.com/ic4y/cyphrmask-oidc-poc/bridge/storage"
)

var testUsers = map[string]storage.TestUser{
	"cLj8vsYtMBwYkzoFVZHBZo6SNL5hTN0OU1ygWJdBJak": {
		PublicKey: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----",
		Email:     "test@example.com",
	},
}

func HandleChallenge(store *ChallengeStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.RemoteAddr
		nonce := GenerateNonce()
		store.Store(sessionID, nonce)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"nonce":   nonce,
			"session": sessionID,
			"expires": time.Now().Add(store.ttl).Format(time.RFC3339),
		})
	}
}

func HandleVerify(store *ChallengeStore, oidcStore *storage.Storage, usersJSON string) http.HandlerFunc {
	users := loadUsers(usersJSON)

	return func(w http.ResponseWriter, r *http.Request) {
		var rawBody map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&rawBody); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		payRaw, ok := rawBody["pay"]
		if !ok {
			http.Error(w, "missing 'pay' field", http.StatusBadRequest)
			return
		}

		sigRaw, ok := rawBody["sig"]
		if !ok {
			http.Error(w, "missing 'sig' field", http.StatusBadRequest)
			return
		}

		var pay struct {
			Alg   string `json:"alg"`
			Tmb   string `json:"tmb"`
			Typ   string `json:"typ"`
			Now   int64  `json:"now"`
			Nonce string `json:"nonce"`
		}
		if err := json.Unmarshal(payRaw, &pay); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		if err := crypto.VerifyTimeliness(pay.Now, time.Minute); err != nil {
			log.Printf("Coz timeliness check failed: %v", err)
			http.Error(w, "timestamp out of range", http.StatusUnauthorized)
			return
		}

		sessionID := r.RemoteAddr
		storedNonce, ok := store.Get(sessionID)
		if !ok {
			http.Error(w, "session expired or invalid", http.StatusUnauthorized)
			return
		}
		if pay.Nonce != storedNonce {
			http.Error(w, "nonce mismatch", http.StatusUnauthorized)
			return
		}
		store.Delete(sessionID)

		payBytes := []byte(payRaw)

		user, ok := users[pay.Tmb]
		if !ok {
			http.Error(w, "unknown key thumbprint", http.StatusUnauthorized)
			return
		}

		var sigStr string
		if err := json.Unmarshal(sigRaw, &sigStr); err != nil {
			http.Error(w, "invalid signature encoding", http.StatusBadRequest)
			return
		}

		if err := crypto.VerifyCozSignature(payBytes, sigStr, user.PublicKey); err != nil {
			log.Printf("Coz signature verification failed: %v", err)
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}

		// Complete the OIDC auth request with thumbprint as subject and email in claims
		authReqID := r.URL.Query().Get("authRequestID")
		if authReqID != "" {
			oidcStore.CompleteAuthRequest(authReqID, pay.Tmb, user.Email)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"email":     user.Email,
			"tmb":       pay.Tmb,
			"authReqID": authReqID,
		})
	}
}

func loadUsers(usersJSON string) map[string]storage.TestUser {
	users := make(map[string]storage.TestUser)
	for k, v := range testUsers {
		users[k] = v
	}

	if usersJSON == "" {
		return users
	}

	var envUsers map[string]storage.TestUser
	if err := json.Unmarshal([]byte(usersJSON), &envUsers); err != nil {
		log.Printf("failed to parse BRIDGE_USERS: %v", err)
		return users
	}

	for k, v := range envUsers {
		users[k] = v
	}

	log.Printf("loaded %d users (%d from env)", len(users), len(envUsers))
	return users
}
