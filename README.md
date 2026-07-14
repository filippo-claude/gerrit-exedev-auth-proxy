# gerrit-exedev-auth-proxy

A small reverse proxy that lets Gerrit use [exe.dev](https://exe.dev/) web authentication for both browsers and Git smart HTTP.

It is designed for a public exe.dev HTTP proxy in front of a loopback-only Gerrit configured with:

```ini
[auth]
    type = HTTP
    httpHeader = X-ExeDev-Email
    emailFormat = {0}
```

## How it works

* Browser requests carrying `X-ExeDev-Email` are proxied to Gerrit with that trusted identity.
* Unauthenticated browser requests are redirected through `/__exe.dev/login`.
* Unauthenticated Git smart-HTTP requests get `401 Unauthorized`, which invokes Git's credential helpers.
* [`git-credential-oauth`](https://github.com/hickford/git-credential-oauth) uses this proxy's OAuth 2.0 authorization-code flow with PKCE.
* The authorization page identifies the user from `X-ExeDev-Email` and returns a one-time code to the helper's loopback callback.
* The token endpoint exchanges that code for a 22-hour opaque token generated with `crypto/rand.Text()`.
* Tokens and authorization codes are kept only in memory. Restarting the service invalidates all of them.
* A valid token is mapped back to its email address and proxied to Gerrit as `X-ExeDev-Email`.

Gerrit never receives the OAuth token or the client's `Authorization` header.

## Client setup

Install a recent version of `git-credential-oauth`, then configure this Gerrit host:

```sh
git config --global credential.https://geomys-gerrit.exe.xyz.oauthClientId git-credential-oauth
git config --global credential.https://geomys-gerrit.exe.xyz.oauthAuthURL /oauth/authorize
git config --global credential.https://geomys-gerrit.exe.xyz.oauthTokenURL /oauth/token
```

Configure credential helpers explicitly:

```sh
# Ignore the error if no global helper was configured.
git config --global --unset-all credential.helper || :

# Reset helpers inherited from lower-priority system configuration.
git config --global --add credential.helper ""

# Keep the token in memory for its 22-hour server lifetime.
git config --global --add credential.helper "cache --timeout 79200"

# Run the OAuth flow when the cache is empty.
git config --global --add credential.helper oauth
```

The empty helper is important. As discussed in
[`git-credential-oauth` issue #92](https://github.com/hickford/git-credential-oauth/issues/92),
a lower-priority Git configuration can install a persistent helper even after
`--unset-all` changes the global configuration. Homebrew Git on macOS, for
example, can inherit `osxkeychain` from `/opt/homebrew/etc/gitconfig`. An empty
`credential.helper` entry resets the inherited helper list before adding the
intended in-memory cache and OAuth helper.

Check the effective configuration, including its source files:

```sh
git config --show-origin --get-all credential.helper
```

Expected values at the end of the output are an empty helper, `cache`, and
`oauth`, in that order.

Then clone normally:

```sh
git clone https://geomys-gerrit.exe.xyz/PROJECT
```

On first use, `git-credential-oauth` prints and normally opens an exe.dev URL.
Log in with an email address that has access to the VM. The local callback then
returns the credential to Git.

### Clearing a cached credential

```sh
git credential-cache exit
```

Because the recommended setup resets inherited helpers, the token is not also
silently saved to a system keychain. Restarting the proxy invalidates every
issued token regardless of client-side caching.

## Server usage

```sh
go build ./cmd/gerrit-exedev-auth-proxy
./gerrit-exedev-auth-proxy \
  -listen :8000 \
  -upstream http://127.0.0.1:8081 \
  -external-url https://geomys-gerrit.exe.xyz \
  -token-lifetime 22h
```

The Gerrit HTTP listener must be reachable only by trusted local processes.
The proxy deliberately trusts `X-ExeDev-Email` supplied by the documented
exe.dev HTTPS proxy.

## Deployment with systemd

Build and install the binary and unit:

```sh
go build -trimpath -ldflags='-s -w' -o gerrit-exedev-auth-proxy ./cmd/gerrit-exedev-auth-proxy
sudo install -o root -g root -m 0755 gerrit-exedev-auth-proxy /usr/local/bin/gerrit-exedev-auth-proxy
sudo install -o root -g root -m 0644 gerrit-exedev-auth-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gerrit-exedev-auth-proxy
```

Make the exe.dev proxy public only after verifying the service locally. Public
access is necessary so an unauthenticated Git client can reach the `401`
challenge and OAuth endpoints; browser authentication is still enforced by the
application redirect.

```sh
ssh exe.dev share set-public geomys-gerrit
```

### Rollback

To return to the previous nginx listener on port 8000:

```sh
sudo systemctl disable --now gerrit-exedev-auth-proxy
sudo systemctl start nginx
```

If the exe.dev endpoint should no longer be public:

```sh
ssh exe.dev share set-private geomys-gerrit
```

## Endpoints

* `GET /oauth/authorize` — OAuth authorization endpoint; requires exe.dev login.
* `POST /oauth/token` — authorization-code exchange.
* `GET /_healthz` — liveness check.
* Everything else — authenticated reverse proxy to Gerrit.

Only the public client ID `git-credential-oauth`, loopback HTTP redirect URIs,
and PKCE `S256` are accepted. Authorization codes expire after five minutes
and are consumed on the first exchange attempt.

## Tests

```sh
go test ./...
go vet ./...
```
