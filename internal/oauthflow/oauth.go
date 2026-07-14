package oauthflow

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/filippo-claude/gerrit-exedev-auth-proxy/internal/store"
)

const ClientID = "git-credential-oauth"

type Code struct {
	Email         string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
}

type Service struct {
	codes         *store.Store[Code]
	tokens        *store.Store[string]
	codeLifetime  time.Duration
	tokenLifetime time.Duration
}

func New(codeLifetime, tokenLifetime time.Duration) *Service {
	return &Service{
		codes: store.New[Code](), tokens: store.New[string](),
		codeLifetime: codeLifetime, tokenLifetime: tokenLifetime,
	}
}

func (s *Service) IssueCode(code Code) string {
	return s.codes.Issue(code, s.codeLifetime)
}

func (s *Service) Exchange(code, clientID, redirectURI, verifier string) (string, time.Duration, error) {
	entry, ok := s.codes.Consume(code)
	if !ok {
		return "", 0, errors.New("invalid or expired authorization code")
	}
	if clientID != entry.ClientID || redirectURI != entry.RedirectURI {
		return "", 0, errors.New("authorization code binding mismatch")
	}
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if challenge != entry.CodeChallenge {
		return "", 0, errors.New("PKCE verification failed")
	}
	return s.tokens.Issue(entry.Email, s.tokenLifetime), s.tokenLifetime, nil
}

func (s *Service) Authenticate(token string) (string, bool) {
	return s.tokens.Lookup(token)
}

func (s *Service) Cleanup() {
	s.codes.Cleanup()
	s.tokens.Cleanup()
}

func ValidateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" {
		return errors.New("redirect_uri must be an HTTP loopback URL")
	}
	host := u.Hostname()
	if !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("redirect_uri must use a loopback host")
		}
	}
	if u.Port() == "" {
		return errors.New("redirect_uri must include a loopback port")
	}
	return nil
}
