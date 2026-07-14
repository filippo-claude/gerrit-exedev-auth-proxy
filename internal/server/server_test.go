package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/filippo-claude/gerrit-exedev-auth-proxy/internal/oauthflow"
)

func testServer(t *testing.T) (*httptest.Server, *oauthflow.Service) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"email":         r.Header.Get("X-ExeDev-Email"),
			"authorization": r.Header.Get("Authorization"),
		})
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	external, _ := url.Parse("https://gerrit.example")
	oauth := oauthflow.New(5*time.Minute, 22*time.Hour)
	s := New(Config{Upstream: upstreamURL, ExternalURL: external, OAuth: oauth, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	proxy := httptest.NewServer(s.Handler())
	t.Cleanup(proxy.Close)
	return proxy, oauth
}

func TestBrowserAndGitUnauthenticated(t *testing.T) {
	s, _ := testServer(t)
	client := s.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(s.URL + "/dashboard?x=1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/__exe.dev/login?") {
		t.Fatalf("browser response = %d, Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()
	resp, err = client.Get(s.URL + "/repo/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("git response = %d, auth %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	resp.Body.Close()
}

func TestExeDevHeaderAndTokenAuthentication(t *testing.T) {
	s, oauth := testServer(t)
	req, _ := http.NewRequest("GET", s.URL+"/", nil)
	req.Header.Set("X-ExeDev-Email", "alice@example.com")
	resp, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got["email"] != "alice@example.com" {
		t.Fatalf("email = %q", got["email"])
	}

	verifier := "this-is-a-long-enough-test-verifier"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	redirect := "http://127.0.0.1:12345/"
	code := oauth.IssueCode(oauthflow.Code{Email: "bob@example.com", ClientID: oauthflow.ClientID, RedirectURI: redirect, CodeChallenge: challenge})
	token, _, err := oauth.Exchange(code, oauthflow.ClientID, redirect, verifier)
	if err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest("GET", s.URL+"/repo/info/refs?service=git-upload-pack", nil)
	req.SetBasicAuth("oauth2", token)
	resp, err = s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got["email"] != "bob@example.com" || got["authorization"] != "" {
		t.Fatalf("upstream headers = %#v", got)
	}
}

func TestAuthorizationEndpoint(t *testing.T) {
	s, _ := testServer(t)
	verifier := "this-is-a-long-enough-test-verifier"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	q := url.Values{
		"response_type": {"code"}, "client_id": {oauthflow.ClientID},
		"redirect_uri": {"http://127.0.0.1:23456/"}, "state": {"state123"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	req, _ := http.NewRequest("GET", s.URL+"/oauth/authorize?"+q.Encode(), nil)
	req.Header.Set("X-ExeDev-Email", "alice@example.com")
	client := s.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	location, _ := url.Parse(resp.Header.Get("Location"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || location.Query().Get("code") == "" || location.Query().Get("state") != "state123" {
		t.Fatalf("authorization redirect = %d %q", resp.StatusCode, location)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {oauthflow.ClientID}, "redirect_uri": {"http://127.0.0.1:23456/"}, "code": {location.Query().Get("code")}, "code_verifier": {verifier}}
	resp, err = client.Post(s.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	var tokenResponse map[string]any
	json.NewDecoder(resp.Body).Decode(&tokenResponse)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || tokenResponse["access_token"] == "" || tokenResponse["expires_in"] != float64(79200) {
		t.Fatalf("token response = %d %#v", resp.StatusCode, tokenResponse)
	}
}
