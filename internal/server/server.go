package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/filippo-claude/gerrit-exedev-auth-proxy/internal/oauthflow"
)

type Config struct {
	Upstream    *url.URL
	ExternalURL *url.URL
	OAuth       *oauthflow.Service
	Logger      *slog.Logger
}

type Server struct {
	cfg   Config
	proxy *httputil.ReverseProxy
}

func New(cfg Config) *Server {
	p := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			email := pr.In.Header.Get("X-Proxy-Authenticated-Email")
			pr.SetURL(cfg.Upstream)
			pr.Out.Host = cfg.ExternalURL.Host
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("X-ExeDev-Email")
			pr.Out.Header.Del("X-ExeDev-UserID")
			pr.Out.Header.Del("X-Proxy-Authenticated-Email")
			pr.Out.Header.Set("X-ExeDev-Email", email)
			pr.Out.Header.Set("X-Forwarded-Proto", cfg.ExternalURL.Scheme)
			pr.Out.Header.Set("X-Forwarded-Host", cfg.ExternalURL.Host)
			pr.SetXForwarded()
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			cfg.Logger.Error("upstream request failed", "error", err)
			http.Error(w, "Bad gateway", http.StatusBadGateway)
		},
	}
	return &Server{cfg: cfg, proxy: p}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /oauth/authorize", s.authorize)
	mux.HandleFunc("POST /oauth/authorize", s.authorizeDecision)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("/", s.proxyRequest)
	return securityHeaders(mux)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	email := r.Header.Get("X-ExeDev-Email")
	if email == "" {
		s.loginRedirect(w, r)
		return
	}
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	if q.Get("response_type") != "code" || q.Get("client_id") != oauthflow.ClientID ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		oauthflow.ValidateRedirectURI(redirectURI) != nil {
		http.Error(w, "Invalid OAuth authorization request", http.StatusBadRequest)
		return
	}
	confirmation := s.cfg.OAuth.RequestConfirmation(oauthflow.Code{
		Email: email, ClientID: oauthflow.ClientID, RedirectURI: redirectURI,
		CodeChallenge: q.Get("code_challenge"), State: q.Get("state"),
	})
	redirect, _ := url.Parse(redirectURI)
	data := authorizationPageData{
		Email: email, GerritHost: s.cfg.ExternalURL.Hostname(), HelperAddress: redirect.Host,
		Confirmation: confirmation,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	if err := authorizationPage.Execute(w, data); err != nil {
		s.cfg.Logger.Error("render authorization confirmation", "error", err)
	}
}

func (s *Server) authorizeDecision(w http.ResponseWriter, r *http.Request) {
	email := r.Header.Get("X-ExeDev-Email")
	if email == "" {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid authorization decision", http.StatusBadRequest)
		return
	}
	if r.Form.Get("decision") != "approve" {
		if err := s.cfg.OAuth.DenyConfirmation(r.Form.Get("confirmation"), email); err != nil {
			http.Error(w, "Invalid or expired authorization confirmation", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<!doctype html><title>Token request denied</title><p>Token request denied. You may close this window.</p>"))
		return
	}
	code, entry, err := s.cfg.OAuth.ApproveConfirmation(r.Form.Get("confirmation"), email)
	if err != nil {
		http.Error(w, "Invalid or expired authorization confirmation", http.StatusBadRequest)
		return
	}
	u, _ := url.Parse(entry.RedirectURI)
	out := u.Query()
	out.Set("code", code)
	if entry.State != "" {
		out.Set("state", entry.State)
	}
	u.RawQuery = out.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

type authorizationPageData struct {
	Email, GerritHost, HelperAddress, Confirmation string
}

var authorizationPage = template.Must(template.New("authorization").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize credential helper</title>
<style>body{font:16px system-ui,sans-serif;max-width:42rem;margin:10vh auto;padding:0 1.5rem;line-height:1.5;color:#202124}main{border:1px solid #dadce0;border-radius:12px;padding:2rem}h1{font-size:1.4rem;margin-top:0}.actions{display:flex;gap:.75rem;margin-top:1.5rem}button{font:inherit;padding:.65rem 1rem;border-radius:6px;border:1px solid #aaa;background:white;cursor:pointer}.approve{background:#1769e0;color:white;border-color:#1769e0}</style>
</head><body><main><h1>Authorize credential helper?</h1>
<p>Do you want to mint a token that will authenticate you as <strong>{{.Email}}</strong> for <strong>{{.GerritHost}}</strong> and provide it to the credential helper running at <strong>{{.HelperAddress}}</strong>?</p>
<form method="post" action="/oauth/authorize"><input type="hidden" name="confirmation" value="{{.Confirmation}}"><div class="actions"><button class="approve" type="submit" name="decision" value="approve">Mint token</button><button type="submit" name="decision" value="deny">Deny</button></div></form>
</main></body></html>`))

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", http.StatusBadRequest)
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		oauthError(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}
	clientID := r.Form.Get("client_id")
	if basicID, _, ok := r.BasicAuth(); ok && clientID == "" {
		clientID = basicID
	}
	token, lifetime, err := s.cfg.OAuth.Exchange(r.Form.Get("code"), clientID, r.Form.Get("redirect_uri"), r.Form.Get("code_verifier"))
	if err != nil {
		oauthError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": token, "token_type": "Bearer", "expires_in": int64(lifetime / time.Second),
	})
}

func (s *Server) proxyRequest(w http.ResponseWriter, r *http.Request) {
	email := r.Header.Get("X-ExeDev-Email")
	if email == "" {
		token := bearerToken(r)
		if token != "" {
			email, _ = s.cfg.OAuth.Authenticate(token)
		}
	}
	if email == "" {
		if isGitRequest(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Gerrit"`)
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		s.loginRedirect(w, r)
		return
	}
	r.Header.Set("X-Proxy-Authenticated-Email", email)
	s.proxy.ServeHTTP(w, r)
}

func (s *Server) loginRedirect(w http.ResponseWriter, r *http.Request) {
	login := &url.URL{Path: "/__exe.dev/login"}
	q := login.Query()
	q.Set("redirect", r.URL.RequestURI())
	login.RawQuery = q.Encode()
	http.Redirect(w, r, login.String(), http.StatusFound)
}

func bearerToken(r *http.Request) string {
	if user, pass, ok := r.BasicAuth(); ok && user != "" {
		return pass
	}
	const prefix = "Bearer "
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	}
	return ""
}

func isGitRequest(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Query().Get("service"), "git-") {
		return true
	}
	return strings.HasSuffix(r.URL.Path, "/git-upload-pack") || strings.HasSuffix(r.URL.Path, "/git-receive-pack")
}

func oauthError(w http.ResponseWriter, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func HTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: addr, Handler: handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          nil,
	}
}

func ParseDurationSeconds(v string, fallback time.Duration) (time.Duration, error) {
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid positive duration in seconds: %q", v)
	}
	return time.Duration(n) * time.Second, nil
}
