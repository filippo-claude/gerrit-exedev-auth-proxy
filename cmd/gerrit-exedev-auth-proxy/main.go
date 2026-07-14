package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/filippo-claude/gerrit-exedev-auth-proxy/internal/oauthflow"
	"github.com/filippo-claude/gerrit-exedev-auth-proxy/internal/server"
)

func main() {
	listen := flag.String("listen", ":8000", "HTTP listen address")
	upstreamRaw := flag.String("upstream", "http://127.0.0.1:8081", "Gerrit upstream URL")
	externalRaw := flag.String("external-url", "", "public base URL (required)")
	tokenLifetimeRaw := flag.String("token-lifetime", "22h", "OAuth access token lifetime")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	upstream, err := url.Parse(*upstreamRaw)
	if err != nil {
		logger.Error("invalid upstream URL", "error", err)
		os.Exit(2)
	}
	external, err := url.Parse(*externalRaw)
	if err != nil || external.Scheme == "" || external.Host == "" {
		logger.Error("invalid external URL", "error", err)
		os.Exit(2)
	}
	tokenLifetime, err := time.ParseDuration(*tokenLifetimeRaw)
	if err != nil || tokenLifetime <= 0 {
		logger.Error("invalid token lifetime", "value", *tokenLifetimeRaw)
		os.Exit(2)
	}

	oauth := oauthflow.New(5*time.Minute, tokenLifetime)
	srv := server.New(server.Config{Upstream: upstream, ExternalURL: external, OAuth: oauth, Logger: logger})
	httpServer := server.HTTPServer(*listen, srv.Handler())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				oauth.Cleanup()
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdown)
	}()

	logger.Info("listening", "address", *listen, "upstream", upstream, "external_url", external, "token_lifetime", tokenLifetime)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}
