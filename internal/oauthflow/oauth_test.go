package oauthflow

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func TestExchange(t *testing.T) {
	s := New(time.Minute, 22*time.Hour)
	verifier := "this-is-a-long-enough-test-verifier"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	redirect := "http://127.0.0.1:12345/"
	code := s.IssueCode(Code{Email: "alice@example.com", ClientID: ClientID, RedirectURI: redirect, CodeChallenge: challenge})
	token, lifetime, err := s.Exchange(code, ClientID, redirect, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if lifetime != 22*time.Hour {
		t.Fatalf("lifetime = %v", lifetime)
	}
	if email, ok := s.Authenticate(token); !ok || email != "alice@example.com" {
		t.Fatalf("Authenticate = %q, %v", email, ok)
	}
	if _, _, err := s.Exchange(code, ClientID, redirect, verifier); err == nil {
		t.Fatal("authorization code replay succeeded")
	}
}

func TestExchangeRejectsPKCEMismatch(t *testing.T) {
	s := New(time.Minute, time.Hour)
	code := s.IssueCode(Code{Email: "alice@example.com", ClientID: ClientID, RedirectURI: "http://localhost:1234/", CodeChallenge: "wrong"})
	if _, _, err := s.Exchange(code, ClientID, "http://localhost:1234/", "verifier"); err == nil {
		t.Fatal("PKCE mismatch succeeded")
	}
}

func TestValidateRedirectURI(t *testing.T) {
	valid := []string{"http://127.0.0.1:1234/", "http://localhost:9999/callback", "http://[::1]:4567/"}
	for _, uri := range valid {
		if err := ValidateRedirectURI(uri); err != nil {
			t.Errorf("ValidateRedirectURI(%q): %v", uri, err)
		}
	}
	invalid := []string{"https://127.0.0.1:1234/", "http://example.com:1234/", "http://localhost/", "http://user@localhost:1234/"}
	for _, uri := range invalid {
		if err := ValidateRedirectURI(uri); err == nil {
			t.Errorf("ValidateRedirectURI(%q) succeeded", uri)
		}
	}
}
