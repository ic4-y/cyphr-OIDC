package storage

import (
	"context"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// CreateTestAuthRequest creates and stores an auth request with the given ID for testing.
func (s *Storage) CreateTestAuthRequest(id, clientID, redirectURI, state string) *AuthRequest {
	req := &AuthRequest{
		ID:           id,
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		State:        state,
		Scopes:       []string{"openid", "profile", "email"},
		ResponseType: oidc.ResponseTypeCode,
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	s.authRequests[id] = req
	return req
}

// CompleteTestAuthRequest marks the auth request as completed for testing.
func (s *Storage) CompleteTestAuthRequest(id, subject, email string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if req, ok := s.authRequests[id]; ok {
		req.UserID = subject
		req.Email = email
		req.ApplicationID = req.ClientID
		req.completed = true
	}
}

// AuthCodeByRequestID returns the auth request ID for a given code (for testing).
func (s *Storage) AuthCodeByRequestID(code string) (string, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	id, ok := s.codes[code]
	return id, ok
}

// SetTestClientCredentials sets client credentials for testing authorization.
func (s *Storage) SetTestClientCredentials(clientID, secret string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if c, ok := s.clients[clientID]; ok {
		c.secret = secret
	}
}

// TestCreateAuthRequest creates an auth request via the OIDC interface for testing.
func (s *Storage) TestCreateAuthRequest(ctx context.Context, id, clientID, redirectURI, state, nonce string) (*AuthRequest, error) {
	oidcReq := &oidc.AuthRequest{
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		State:        state,
		Nonce:        nonce,
		Scopes:       []string{"openid", "profile", "email"},
		ResponseType: oidc.ResponseTypeCode,
	}
	result, err := s.CreateAuthRequest(ctx, oidcReq, "")
	if err != nil {
		return nil, err
	}
	// Override the ID for predictability
	s.lock.Lock()
	defer s.lock.Unlock()
	ar := result.(*AuthRequest)
	delete(s.authRequests, ar.ID)
	ar.ID = id
	s.authRequests[id] = ar
	return ar, nil
}
