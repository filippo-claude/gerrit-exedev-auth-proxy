package server

import (
	"encoding/json"
	"fmt"
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
	code := s.cfg.OAuth.IssueCode(oauthflow.Code{
		Email: email, ClientID: oauthflow.ClientID, RedirectURI: redirectURI,
		CodeChallenge: q.Get("code_challenge"),
	})
	u, _ := url.Parse(redirectURI)
	out := u.Query()
	out.Set("code", code)
	if state := q.Get("state"); state != "" {
		out.Set("state", state)
	}
	u.RawQuery = out.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

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
