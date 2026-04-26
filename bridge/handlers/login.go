package handlers

import (
	"html/template"
	"log"
	"net/http"

	"github.com/ic4y/cyphrmask-oidc-poc/bridge/storage"
)

type LoginHandler struct {
	store     *storage.Storage
	templates *template.Template
	issuer    string
}

func NewLoginHandler(store *storage.Storage, templates *template.Template, issuer string) *LoginHandler {
	return &LoginHandler{
		store:     store,
		templates: templates,
		issuer:    issuer,
	}
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authReqID := r.URL.Query().Get("authRequestID")
	if authReqID == "" {
		http.Error(w, "missing authRequestID", http.StatusBadRequest)
		return
	}

	req, err := h.store.AuthRequestByID(r.Context(), authReqID)
	if err != nil {
		log.Printf("login handler: auth request not found: %v", err)
		http.Error(w, "invalid auth request", http.StatusBadRequest)
		return
	}

	data := struct {
		AuthRequestID string
		ClientID      string
		Issuer        string
		RedirectURI   string
		State         string
	}{
		AuthRequestID: authReqID,
		ClientID:      req.GetClientID(),
		Issuer:        h.issuer,
		RedirectURI:   req.GetRedirectURI(),
		State:         req.GetState(),
	}

	w.Header().Set("Content-Type", "text/html")
	if err := h.templates.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Printf("login handler: template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}
