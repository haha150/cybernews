# CyberNews Aggregator

A self-hosted cybersecurity news aggregator dashboard that pulls the latest
CVEs, vulnerabilities, exploits, threat intelligence, and security research
from 150+ RSS/Atom feeds in near real-time.

## Quick Start

```bash
cp .env.example .env
docker compose up --build
```

Open **http://localhost:8080** in your browser.

## Features

- **150+ curated security feeds** — news, CVEs, red team, threat intel, government advisories
- **PoC/Exploit enrichment** — automatic lookup via PoC-in-GitHub, CISA KEV, Exploit-DB
- **CVSS severity badges** — sourced from NVD API when available
- **Full-text search** across all cached articles
- **Category filtering** — All, CVE/Vulns, Red Team, Threat Intel, News, Government, Research
- **Source management** — enable/disable feeds, add custom sources, view health status
- **Feed discovery** — scan curated GitHub lists for new security RSS feeds
- **OPML export** — import your feed list into any RSS reader
- **Dark mode UI** — terminal/hacker aesthetic with monospace accents
- **Responsive** — 3-column grid → tablet → mobile
- **Deduplication** — skips articles with duplicate URLs or title+source
- **Toast notifications** when new articles arrive
- **Fully containerized** — single `docker compose up` command
- **TLS ready** — drop your cert/key into `certs/` for automatic HTTPS
- **Optional auth** — HTTP Basic Auth via env vars
- **Fail2ban** — auto-bans IPs after repeated failed login attempts
- **Rate limiting** on mutating API endpoints
- **GZip compression** for API responses

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌────────────┐
│   Browser    │────▶│  nginx (frontend) │────▶│  FastAPI    │
│              │     │  :80 / :443 (TLS)│     │  (backend)  │
│  Vanilla JS  │     │  /api/* → proxy   │     │  :8000      │
└──────────────┘     └──────────────────┘     └─────┬──────┘
                                                     │
                                          ┌──────────┴────────┐
                                          │   SQLite (volume)  │
                                          │   /app/data/       │
                                          └───────────────────┘
                                                     │
                                          ┌──────────┴────────┐
                                          │  APScheduler       │
                                          │  ├─ Feed refresh   │
                                          │  ├─ CVE enrichment │
                                          │  ├─ KEV catalog    │
                                          │  └─ Article cleanup│
                                          └───────────────────┘
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BACKEND_PORT` | `8000` | Backend API port |
| `FRONTEND_PORT` | `8080` | Frontend web UI port (HTTP) |
| `HTTPS_PORT` | `8443` | Frontend web UI port (HTTPS) |
| `SSL_CERT_DIR` | `./certs` | Directory containing `cert.pem` and `key.pem` |
| `DB_PATH` | `/app/data/cybernews.db` | SQLite database path |
| `DB_POOL_SIZE` | `5` | Connection pool size |
| `RETENTION_DAYS` | `30` | Auto-delete articles older than this |
| `REFRESH_INTERVAL_MINUTES` | `15` | Feed refresh interval |
| `ENRICHMENT_INTERVAL_MINUTES` | `5` | CVE enrichment check interval |
| `ENRICHMENT_TTL_HOURS` | `6` | Cache TTL for enrichment data |
| `NVD_API_KEY` | *(empty)* | NVD API key for higher rate limits |
| `FEEDS_PATH` | `feeds.json` | Path to feed sources config |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `AUTH_USERNAME` | *(empty)* | HTTP Basic Auth username (leave empty to disable) |
| `AUTH_PASSWORD` | *(empty)* | HTTP Basic Auth password |
| `RATE_LIMIT_RPM` | `30` | Max requests/min on mutating endpoints |
| `FAIL2BAN_MAX_ATTEMPTS` | `5` | Failed logins before IP is banned |
| `FAIL2BAN_WINDOW` | `300` | Time window (seconds) for counting failed attempts |
| `FAIL2BAN_BAN_TIME` | `900` | Ban duration (seconds) after max attempts exceeded |

## TLS / HTTPS

To enable HTTPS, place your certificate and key in the `certs/` directory:

```bash
# Self-signed (testing)
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes -subj "/CN=cybernews.local"

# Let's Encrypt
cp /etc/letsencrypt/live/yourdomain/fullchain.pem certs/cert.pem
cp /etc/letsencrypt/live/yourdomain/privkey.pem certs/key.pem
```

When certs are present, nginx automatically enables HTTPS on port 8443 (configurable via `HTTPS_PORT`) and redirects HTTP → HTTPS. Without certs, it serves HTTP only.

## Getting an NVD API Key

1. Go to https://nvd.nist.gov/developers/request-an-api-key
2. Fill in the form and confirm via email
3. Set `NVD_API_KEY` in your `.env` file
4. This increases NVD rate limits from 5 to 50 requests per 30 seconds

## Fail2ban (Brute-Force Protection)

When HTTP Basic Auth is enabled, the backend tracks failed login attempts per IP.
After 5 failures within 5 minutes (configurable), the IP is banned for 15 minutes.
Bans are stored in-memory and automatically expire. The `/api/stats` healthcheck
endpoint is exempt from bans so container health checks continue to work.

## Adding Feeds

Edit `feeds.json` to add sources to the hardcoded list, or use the web UI:

1. Click the ⚙️ button in the sidebar
2. Fill in Name, URL, and Category
3. Click "Add Source"

The app will auto-detect RSS/Atom feeds from plain website URLs.

## Makefile Targets

```bash
make up        # Build and start all services
make down      # Stop all services
make logs      # Follow container logs
make rebuild   # Full rebuild (no cache)
make shell     # Shell into backend container
```

## API Endpoints

```
GET  /api/articles     ?category= &search= &poc_only= &page= &limit=
GET  /api/sources      List all sources with health status
POST /api/sources      Add a custom source
PUT  /api/sources/:id  Update source (enable/disable)
DELETE /api/sources/:id  Remove custom source
POST /api/refresh      Trigger manual feed refresh
GET  /api/cve/:id/poc  Get PoC enrichment for a CVE
GET  /api/stats        Dashboard statistics
GET  /api/opml         Export all sources as OPML
GET  /api/discover     Discover new feeds from curated lists
```

## Tech Stack

- **Backend**: Python 3.12, FastAPI, feedparser, httpx, aiosqlite, APScheduler
- **Frontend**: Vanilla JS, Inter + JetBrains Mono fonts, CSS Grid
- **Database**: SQLite with WAL mode
- **Proxy**: nginx (reverse proxy + static file server)
- **Container**: Docker multi-stage build, Docker Compose

## License

MIT
