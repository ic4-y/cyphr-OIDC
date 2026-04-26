package storage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

var (
	_ op.Storage                  = &Storage{}
	_ op.ClientCredentialsStorage = &Storage{}
)

type Storage struct {
	lock          sync.Mutex
	authRequests  map[string]*AuthRequest
	codes         map[string]string
	tokens        map[string]*Token
	clients       map[string]*Client
	refreshTokens map[string]*RefreshToken
	signingKey    signingKey
}

type signingKey struct {
	id        string
	algorithm jose.SignatureAlgorithm
	key       *rsa.PrivateKey
}

func (s *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return s.algorithm }
func (s *signingKey) Key() any                                    { return s.key }
func (s *signingKey) ID() string                                  { return s.id }

type publicKey struct{ signingKey }

func (s *publicKey) ID() string                         { return s.id }
func (s *publicKey) Algorithm() jose.SignatureAlgorithm { return s.algorithm }
func (s *publicKey) Use() string                        { return "sig" }
func (s *publicKey) Key() any                           { return &s.key.PublicKey }

type AuthRequest struct {
	ID            string
	ClientID      string
	ApplicationID string
	RedirectURI   string
	Scopes        []string
	State         string
	Nonce         string
	UserID        string
	Email         string
	completed     bool
	AuthTime      time.Time
	ResponseType  oidc.ResponseType
}

func (a *AuthRequest) GetID() string                         { return a.ID }
func (a *AuthRequest) GetACR() string                        { return "" }
func (a *AuthRequest) GetAMR() []string                      { return []string{"pwd"} }
func (a *AuthRequest) GetAudience() []string                 { return []string{a.ClientID} }
func (a *AuthRequest) GetAuthTime() time.Time                { return a.AuthTime }
func (a *AuthRequest) GetClientID() string                   { return a.ClientID }
func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge { return nil }
func (a *AuthRequest) GetNonce() string                      { return a.Nonce }
func (a *AuthRequest) GetRedirectURI() string                { return a.RedirectURI }
func (a *AuthRequest) GetResponseType() oidc.ResponseType    { return a.ResponseType }
func (a *AuthRequest) GetResponseMode() oidc.ResponseMode    { return "" }
func (a *AuthRequest) GetScopes() []string                   { return a.Scopes }
func (a *AuthRequest) GetState() string                      { return a.State }
func (a *AuthRequest) GetSubject() string                    { return a.UserID }
func (a *AuthRequest) GetEmail() string                      { return a.Email }
func (a *AuthRequest) Done() bool                            { return a.completed }

type Client struct {
	id              string
	secret          string
	redirectURIs    []string
	applicationType op.ApplicationType
	authMethod      oidc.AuthMethod
	responseTypes   []oidc.ResponseType
	grantTypes      []oidc.GrantType
	accessTokenType op.AccessTokenType
	devMode         bool
	loginURL        func(string) string
}

func NewClient(id, secret string, redirectURIs []string, loginURL func(string) string) *Client {
	return &Client{
		id:              id,
		secret:          secret,
		redirectURIs:    redirectURIs,
		applicationType: op.ApplicationTypeWeb,
		authMethod:      oidc.AuthMethodBasic,
		responseTypes:   []oidc.ResponseType{oidc.ResponseTypeCode, oidc.ResponseTypeIDTokenOnly, oidc.ResponseTypeIDToken},
		grantTypes:      []oidc.GrantType{oidc.GrantTypeCode},
		accessTokenType: op.AccessTokenTypeBearer,
		devMode:         true,
		loginURL:        loginURL,
	}
}

func (c *Client) GetID() string                       { return c.id }
func (c *Client) RedirectURIs() []string              { return c.redirectURIs }
func (c *Client) PostLogoutRedirectURIs() []string    { return []string{} }
func (c *Client) ApplicationType() op.ApplicationType { return c.applicationType }
func (c *Client) AuthMethod() oidc.AuthMethod         { return c.authMethod }
func (c *Client) ResponseTypes() []oidc.ResponseType  { return c.responseTypes }
func (c *Client) GrantTypes() []oidc.GrantType        { return c.grantTypes }
func (c *Client) LoginURL(id string) string           { return c.loginURL(id) }
func (c *Client) AccessTokenType() op.AccessTokenType { return c.accessTokenType }
func (c *Client) IDTokenLifetime() time.Duration      { return 1 * time.Hour }
func (c *Client) DevMode() bool                       { return c.devMode }
func (c *Client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *Client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *Client) IsScopeAllowed(scope string) bool     { return false }
func (c *Client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *Client) ClockSkew() time.Duration             { return 0 }

type Token struct {
	ID             string
	ApplicationID  string
	RefreshTokenID string
	Subject        string
	Email          string
	Audience       []string
	Expiration     time.Time
	Scopes         []string
}

type RefreshToken struct {
	ID            string
	Token         string
	AuthTime      time.Time
	AMR           []string
	ApplicationID string
	UserID        string
	Email         string
	Audience      []string
	Expiration    time.Time
	Scopes        []string
	AccessToken   string
}

type hasRedirectGlobs struct{ *Client }

func (c hasRedirectGlobs) RedirectURIGlobs() []string           { return nil }
func (c hasRedirectGlobs) PostLogoutRedirectURIGlobs() []string { return nil }

func wrapClient(c *Client) op.Client {
	if c.devMode {
		return hasRedirectGlobs{c}
	}
	return c
}

func NewStorage() *Storage {
	return mustNewStorage("")
}

func NewStorageWithKeyPath(path string) *Storage {
	return mustNewStorage(path)
}

func mustNewStorage(keyPath string) *Storage {
	var key *rsa.PrivateKey
	if keyPath != "" {
		var err error
		key, err = loadOrGenerateKey(keyPath)
		if err != nil {
			panic(fmt.Sprintf("failed to load signing key from %s: %v", keyPath, err))
		}
	} else {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(fmt.Sprintf("failed to generate signing key: %v", err))
		}
	}
	return &Storage{
		authRequests:  make(map[string]*AuthRequest),
		codes:         make(map[string]string),
		tokens:        make(map[string]*Token),
		clients:       make(map[string]*Client),
		refreshTokens: make(map[string]*RefreshToken),
		signingKey: signingKey{
			id:        uuid.NewString(),
			algorithm: jose.RS256,
			key:       key,
		},
	}
}

func (s *Storage) RegisterClient(c *Client) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.clients[c.id] = c
}

func (s *Storage) CompleteAuthRequest(id, subject, email string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if req, ok := s.authRequests[id]; ok {
		req.UserID = subject
		req.Email = email
		req.ApplicationID = req.ClientID
		req.completed = true
		req.AuthTime = time.Now()
	}
}

func (s *Storage) CheckUsernamePassword(username, password, id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	request, ok := s.authRequests[id]
	if !ok {
		return fmt.Errorf("request not found")
	}
	_ = username
	_ = password
	request.completed = true
	request.AuthTime = time.Now()
	return nil
}

func (s *Storage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	request := &AuthRequest{
		ID:           uuid.NewString(),
		ClientID:     authReq.ClientID,
		RedirectURI:  authReq.RedirectURI,
		Scopes:       authReq.Scopes,
		State:        authReq.State,
		Nonce:        authReq.Nonce,
		UserID:       userID,
		ResponseType: authReq.ResponseType,
	}
	s.authRequests[request.ID] = request
	return request, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	req, ok := s.authRequests[id]
	if !ok {
		return nil, fmt.Errorf("auth request not found")
	}
	return req, nil
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	requestID, ok := func() (string, bool) {
		s.lock.Lock()
		defer s.lock.Unlock()
		id, ok := s.codes[code]
		return id, ok
	}()
	if !ok {
		return nil, fmt.Errorf("code invalid or expired")
	}
	return s.AuthRequestByID(ctx, requestID)
}

func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.codes[code] = id
	return nil
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.authRequests, id)
	for code, requestID := range s.codes {
		if requestID == id {
			delete(s.codes, code)
			break
		}
	}
	return nil
}

func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	var applicationID, email string
	switch req := request.(type) {
	case *AuthRequest:
		applicationID = req.ApplicationID
		email = req.Email
	}

	token, err := s.createAccessToken(applicationID, "", request.GetSubject(), email, request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID, token.Expiration, nil
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID, newRefreshTokenID string, expiration time.Time, err error) {
	applicationID, authTime, amr := getInfoFromRequest(request)

	var email string
	switch req := request.(type) {
	case *AuthRequest:
		email = req.Email
	case *RefreshTokenRequest:
		email = req.Email
	}

	if currentRefreshToken == "" {
		refreshTokenID := uuid.NewString()
		accessToken, err := s.createAccessToken(applicationID, refreshTokenID, request.GetSubject(), email, request.GetAudience(), request.GetScopes())
		if err != nil {
			return "", "", time.Time{}, err
		}
		refreshToken := s.createRefreshToken(accessToken, amr, authTime)
		return accessToken.ID, refreshToken.ID, accessToken.Expiration, nil
	}

	newRefreshTokenID = uuid.NewString()
	accessToken, err := s.createAccessToken(applicationID, newRefreshTokenID, request.GetSubject(), email, request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", "", time.Time{}, err
	}
	if err := s.renewRefreshToken(currentRefreshToken, newRefreshTokenID, accessToken.ID); err != nil {
		return "", "", time.Time{}, err
	}
	return accessToken.ID, newRefreshTokenID, accessToken.Expiration, nil
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	token, ok := s.refreshTokens[refreshToken]
	if !ok {
		return nil, fmt.Errorf("invalid refresh_token")
	}
	return &RefreshTokenRequest{
		ApplicationID: token.ApplicationID,
		Subject:       token.UserID,
		Email:         token.Email,
		AuthTime:      token.AuthTime,
		AMR:           token.AMR,
		Audience:      token.Audience,
		Scopes:        token.Scopes,
	}, nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, token := range s.tokens {
		if token.ApplicationID == clientID && token.Subject == userID {
			delete(s.tokens, token.ID)
			delete(s.refreshTokens, token.RefreshTokenID)
		}
	}
	return nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	refreshToken, ok := s.refreshTokens[token]
	if !ok {
		return "", "", op.ErrInvalidRefreshToken
	}
	return refreshToken.UserID, refreshToken.ID, nil
}

func (s *Storage) RevokeToken(ctx context.Context, tokenIDOrToken string, userID string, clientID string) *oidc.Error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if accessToken, ok := s.tokens[tokenIDOrToken]; ok {
		if accessToken.ApplicationID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		delete(s.tokens, accessToken.ID)
		return nil
	}
	if refreshToken, ok := s.refreshTokens[tokenIDOrToken]; ok {
		if refreshToken.ApplicationID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		delete(s.refreshTokens, refreshToken.ID)
		delete(s.tokens, refreshToken.AccessToken)
		return nil
	}
	return nil
}

func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	return &s.signingKey, nil
}

func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{s.signingKey.algorithm}, nil
}

func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	return []op.Key{&publicKey{s.signingKey}}, nil
}

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	client, ok := s.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found")
	}
	return wrapClient(client), nil
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	client, ok := s.clients[clientID]
	if !ok {
		return fmt.Errorf("client not found")
	}
	if client.secret != clientSecret {
		return fmt.Errorf("invalid secret")
	}
	return nil
}

func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	userinfo.Subject = userID
	var email string
	for _, req := range s.authRequests {
		if req.UserID == userID && req.Email != "" {
			email = req.Email
			break
		}
	}
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeEmail:
			userinfo.Email = email
			userinfo.EmailVerified = email != ""
		case oidc.ScopeProfile:
			userinfo.PreferredUsername = userID
			userinfo.Name = userID
		}
	}
	return nil
}

func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, token op.IDTokenRequest, scopes []string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	userinfo.Subject = token.GetSubject()
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeEmail:
			if ar, ok := token.(*AuthRequest); ok {
				userinfo.Email = ar.Email
			} else {
				userinfo.Email = token.GetSubject()
			}
			userinfo.EmailVerified = true
		case oidc.ScopeProfile:
			userinfo.PreferredUsername = token.GetSubject()
			userinfo.Name = token.GetSubject()
		}
	}
	return nil
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	token, ok := s.tokens[tokenID]
	if !ok {
		return fmt.Errorf("token not found")
	}
	if token.Expiration.Before(time.Now()) {
		return fmt.Errorf("token expired")
	}
	userinfo.Subject = token.Subject
	for _, scope := range token.Scopes {
		switch scope {
		case oidc.ScopeEmail:
			userinfo.Email = token.Email
			userinfo.EmailVerified = true
		case oidc.ScopeProfile:
			userinfo.PreferredUsername = token.Subject
			userinfo.Name = token.Subject
		}
	}
	return nil
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	token, ok := s.tokens[tokenID]
	if !ok {
		return fmt.Errorf("token not found")
	}
	for _, aud := range token.Audience {
		if aud == clientID {
			introspection.Scope = token.Scopes
			introspection.ClientID = token.ApplicationID
			introspection.Active = true
			return nil
		}
	}
	return fmt.Errorf("token not valid for this client")
}

func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	claims := make(map[string]any)
	var email string
	for _, req := range s.authRequests {
		if req.UserID == userID && req.Email != "" {
			email = req.Email
			break
		}
	}
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeEmail:
			claims["email"] = email
			claims["email_verified"] = email != ""
		case oidc.ScopeProfile:
			claims["preferred_username"] = email
			claims["name"] = email
		}
	}
	return claims, nil
}

func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, fmt.Errorf("no keys registered")
}

func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}

func (s *Storage) Health(ctx context.Context) error {
	return nil
}

func (s *Storage) ClientCredentials(ctx context.Context, clientID, clientSecret string) (op.Client, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	client, ok := s.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found")
	}
	if client.secret != clientSecret {
		return nil, fmt.Errorf("invalid secret")
	}
	return wrapClient(client), nil
}

func (s *Storage) ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (op.TokenRequest, error) {
	return nil, fmt.Errorf("client_credentials grant not supported")
}

func (s *Storage) createAccessToken(applicationID, refreshTokenID, subject, email string, audience, scopes []string) (*Token, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	token := &Token{
		ID:             uuid.NewString(),
		ApplicationID:  applicationID,
		RefreshTokenID: refreshTokenID,
		Subject:        subject,
		Email:          email,
		Audience:       audience,
		Expiration:     time.Now().Add(5 * time.Minute),
		Scopes:         scopes,
	}
	s.tokens[token.ID] = token
	return token, nil
}

func (s *Storage) createRefreshToken(accessToken *Token, amr []string, authTime time.Time) *RefreshToken {
	s.lock.Lock()
	defer s.lock.Unlock()
	token := &RefreshToken{
		ID:            accessToken.RefreshTokenID,
		Token:         accessToken.RefreshTokenID,
		AuthTime:      authTime,
		AMR:           amr,
		ApplicationID: accessToken.ApplicationID,
		UserID:        accessToken.Subject,
		Email:         accessToken.Email,
		Audience:      accessToken.Audience,
		Expiration:    time.Now().Add(5 * time.Hour),
		Scopes:        accessToken.Scopes,
		AccessToken:   accessToken.ID,
	}
	s.refreshTokens[token.ID] = token
	return token
}

func (s *Storage) renewRefreshToken(currentRefreshToken, newRefreshToken, newAccessToken string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	refreshToken, ok := s.refreshTokens[currentRefreshToken]
	if !ok {
		return fmt.Errorf("invalid refresh token")
	}
	delete(s.refreshTokens, currentRefreshToken)
	delete(s.tokens, refreshToken.AccessToken)
	if refreshToken.Expiration.Before(time.Now()) {
		return fmt.Errorf("expired refresh token")
	}
	refreshToken.Token = newRefreshToken
	refreshToken.ID = newRefreshToken
	refreshToken.Expiration = time.Now().Add(5 * time.Hour)
	refreshToken.AccessToken = newAccessToken
	s.refreshTokens[newRefreshToken] = refreshToken
	return nil
}

func getInfoFromRequest(req op.TokenRequest) (clientID string, authTime time.Time, amr []string) {
	authReq, ok := req.(*AuthRequest)
	if ok {
		return authReq.ApplicationID, authReq.AuthTime, authReq.GetAMR()
	}
	refreshReq, ok := req.(*RefreshTokenRequest)
	if ok {
		return refreshReq.ApplicationID, refreshReq.AuthTime, refreshReq.AMR
	}
	return "", time.Time{}, nil
}

type RefreshTokenRequest struct {
	ApplicationID string
	Subject       string
	Email         string
	AuthTime      time.Time
	AMR           []string
	Audience      []string
	Scopes        []string
}

func (r *RefreshTokenRequest) GetAMR() []string                 { return r.AMR }
func (r *RefreshTokenRequest) GetAudience() []string            { return r.Audience }
func (r *RefreshTokenRequest) GetAuthTime() time.Time           { return r.AuthTime }
func (r *RefreshTokenRequest) GetClientID() string              { return r.ApplicationID }
func (r *RefreshTokenRequest) GetScopes() []string              { return r.Scopes }
func (r *RefreshTokenRequest) GetSubject() string               { return r.Subject }
func (r *RefreshTokenRequest) SetCurrentScopes(scopes []string) { r.Scopes = scopes }

func loadOrGenerateKey(path string) (*rsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
		return key, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("failed to save key: %w", err)
	}
	return key, nil
}

// TestUser is a PoC user with their public key and email.
type TestUser struct {
	PublicKey string `json:"public_key"`
	Email     string `json:"email"`
}
