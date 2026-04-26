package handlers

import (
	"log"
	"net/http"

	"github.com/ic4y/cyphrmask-oidc-poc/bridge/storage"
)

// TokenCallbackHandler handles the client's redirect_uri after authorization code is issued.
// In a full OIDC flow, the client would exchange the code for tokens here.
// For this PoC, we just show success.
type TokenCallbackHandler struct {
	store *storage.Storage
}

func NewTokenCallbackHandler(store *storage.Storage) *TokenCallbackHandler {
	return &TokenCallbackHandler{store: store}
}

func (h *TokenCallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	// Look up the auth request to show user info
	req, err := h.store.AuthRequestByCode(r.Context(), code)
	if err != nil {
		log.Printf("token callback: invalid code: %v", err)
		http.Error(w, "invalid or expired code", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Sign In Complete</title>
<style>
body { background: #0f172a; color: #e2e8f0; font-family: system-ui, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
.container { background: #1e293b; border-radius: 12px; padding: 2rem; max-width: 480px; width: 100%; box-shadow: 0 4px 24px rgba(0,0,0,0.4); text-align: center; }
h1 { color: #22c55e; margin: 0 0 1rem; }
p { color: #94a3b8; }
code { background: #0f172a; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.85rem; }
</style></head><body>
<div class="container">
<h1>Authentication Successful</h1>
<p>You have been authenticated via Cyphr-OIDC Bridge.</p>
<p>Subject: <code>` + req.GetSubject() + `</code></p>
<p>State: <code>` + state + `</code></p>
</div></body></html>`))
}
