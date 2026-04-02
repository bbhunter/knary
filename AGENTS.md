# knary - HTTP(S) and DNS Canary Token Server

## Project Overview

knary is a Go canary token server that listens for DNS and HTTP(S) requests matching a configured domain, then sends notifications to webhooks (Slack, Discord, Teams, Lark, Telegram, Pushover). It also supports a **reverse proxy mode** for running tools like Burp Collaborator alongside it.

## Architecture

### Entry Point

`main.go` — loads `.env` via godotenv, resolves the external IP, starts DNS/HTTP/HTTPS listeners, and manages TLS certificates.

### Core Package: `libknary/`

| File | Responsibility |
|------|----------------|
| `http.go` | HTTP/HTTPS listeners, reverse proxy routing, raw TCP request handling (`handleRequest`) |
| `dns.go` | DNS server (`HandleDNS`, `parseDNS`), DNS reverse proxy forwarding |
| `util.go` | Domain matching (`returnSuffix`), IP helpers, update checker, heartbeat messages |
| `webhooks.go` | Webhook delivery to Slack, Discord, Teams, Lark, Telegram, Pushover |
| `notificationctrl.go` | Allow/deny list logic for filtering canary hits |
| `certutil.go` | TLS certificate loading, expiry checks, SAN domain list construction |
| `certbot.go` | Let's Encrypt ACME certificate management |
| `zones.go` | RFC 1034/1035 zone file parsing for custom DNS responses |
| `maintenance.go` | Periodic timers for heartbeat, update checks, denylist alerting |
| `logging.go` | File-based logging |
| `analytics.go` | Anonymous usage telemetry |
| `fsnotify.go` | Filesystem watcher for TLS cert hot-reload |
| `interface.go` | Terminal output helpers (`Printy`, `GiveHead`) |

### HTTP Request Flow (with reverse proxy enabled)

```
Client
  │
  ▼
Public listener (BIND_ADDR:80 or :443)
  httputil.ReverseProxy handler (createReverseProxyHandler)
  │
  ├─ Host matches REVERSE_PROXY_DOMAIN suffix
  │   → Forward to REVERSE_PROXY_HTTP / REVERSE_PROXY_HTTPS backend
  │
  └─ Host matches CANARY_DOMAIN
      → Forward to internal listener (127.0.0.1:8880 or :8843)
        → handleRequest() reads raw TCP, extracts headers, sends webhook
        → httpRespond() returns HTTP/1.1 200 OK
```

Without reverse proxy enabled, clients connect directly to the raw TCP listener on ports 80/443.

### DNS Request Flow

DNS queries arrive via `HandleDNS` → `parseDNS`. If the query name matches `REVERSE_PROXY_DOMAIN`, it's forwarded to `REVERSE_PROXY_DNS`. Otherwise, knary responds with `EXT_IP` for A records and handles SOA/NS queries for the canary domain.

## Key Design Decisions

- **Raw TCP for HTTP handling**: `handleRequest` uses raw `net.Conn` reads (not `net/http`) to capture up to 4KB of request data. This means `httpRespond` must write a valid HTTP response string, not just raw bytes — critical when behind the reverse proxy's `httputil.ReverseProxy`.
- **Reverse proxy splits listeners**: When `REVERSE_PROXY_HTTP` is set, port 80 runs `http.ListenAndServe` with a routing handler, and an internal raw TCP listener binds to `127.0.0.1:8880`. Same pattern for HTTPS on port 443 → `127.0.0.1:8843`.
- **`REVERSE_PROXY_HTTPS` expects a TLS-capable backend**: The env var means "where to forward incoming HTTPS traffic." knary connects to this backend using HTTPS (`InsecureSkipVerify: true` for self-signed certs).
- **Configuration via `os.Getenv()` at call sites**: There is no centralised config struct. All settings are read from environment variables (or `.env` file via godotenv) at the point of use.

## Dependencies

- Update all dependencies: `go get -u ./... && go mod tidy`
- Always run `go build ./...` and `go test ./...` afterwards to verify nothing broke

## Testing

- Run `go test ./...` for unit tests
- For manual testing, use `/etc/hosts` entries or `curl -H "Host: subdomain.knary.tld" http://127.0.0.1`
- Ports 53, 80, 443 require root — use `sudo` when running knary locally
- A Python HTTP server (`python3 -m http.server 8080`) is a useful stand-in for a reverse proxy backend

## Conventions

- No external HTTP framework — standard library `net`, `net/http`, `net/http/httputil`, and `crypto/tls`
- DNS handling uses `github.com/miekg/dns`
- Errors are logged via `logger()` and printed via `Printy(msg, severity)` where severity: 1=info, 2=warning/error, 3=debug
- Webhook messages are sent asynchronously via `go sendMsg()`
