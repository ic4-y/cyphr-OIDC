package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/ic4y/cyphrmask-oidc-poc/bridge/storage"
)

// CallbackHandler handles the redirect after successful Coz verification.
// It creates an authorization code and redirects to the client's redirect_uri.
type CallbackHandler struct {
	store *storage.Storage
}

func NewCallbackHandler(store *storage.Storage) *CallbackHandler {
	return &CallbackHandler{store: store}
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authReqID := r.URL.Query().Get("id")
	if authReqID == "" {
		http.Error(w, "missing auth request id", http.StatusBadRequest)
		return
	}

	req, err := h.store.AuthRequestByID(r.Context(), authReqID)
	if err != nil {
		log.Printf("callback handler: auth request not found: %v", err)
		http.Error(w, "invalid auth request", http.StatusBadRequest)
		return
	}

	// Create the authorization code
	code := genCode()
	if err := h.store.SaveAuthCode(r.Context(), authReqID, code); err != nil {
		log.Printf("callback handler: failed to save auth code: %v", err)
		http.Error(w, "failed to create authorization code", http.StatusInternalServerError)
		return
	}

	// Redirect to client's redirect_uri with the code
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", req.GetRedirectURI(), code, req.GetState())
	log.Printf("callback handler: redirecting to %s", req.GetRedirectURI())
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func genCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
