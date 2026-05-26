# CyberNews Aggregator

A self-hosted cybersecurity news aggregator dashboard that pulls the latest
CVEs, vulnerabilities, exploits, threat intelligence, and security research
from 80+ RSS/Atom feeds in near real-time.

## Quick Start

```bash
cp .env.example .env
docker compose up --build
```

Open **http://localhost:8080** in your browser.

## Features

- **80+ curated security feeds** — news, CVEs, red team, threat intel, government advisories
- **PoC/Exploit enrichment** — automatic lookup via PoC-in-GitHub, CISA KEV, Exploit-DB
- **CVSS severity badges** — sourced from NVD API when available
- **Full-text search** across all cached articles
- **Category filtering** — All, CVE/Vulns, Red Team, Threat Intel, News, Government, Research
- **Source management** — enable/disable feeds, add custom sources, view health status
- **Feed discovery** — scan curated GitHub lists for new security RSS feeds
- **OPML export** — import your feed list into any RSS reader
- **Dark mode UI** — terminal/hacker aesthetic with monospace accents
- **Responsive** — 3-column grid → tablet → mobile
- **Deduplication** — skips articles with duplicate URLs
- **Toast notifications** when new articles arrive
- **Fully containerized** — single `docker compose up` command

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌────────────┐
│   Browser    │────▶│  nginx (frontend) │────▶│  FastAPI    │
│              │     │  :8080            │     │  (backend)  │
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
                                          │  └─ KEV catalog    │
                                          └───────────────────┘
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BACKEND_PORT` | `8000` | Backend API port |
| `FRONTEND_PORT` | `8080` | Frontend web UI port |
| `DB_PATH` | `/app/data/cybernews.db` | SQLite database path |
| `REFRESH_INTERVAL_MINUTES` | `15` | Feed refresh interval |
| `ENRICHMENT_INTERVAL_MINUTES` | `5` | CVE enrichment check interval |
| `ENRICHMENT_TTL_HOURS` | `6` | Cache TTL for enrichment data |
| `NVD_API_KEY` | *(empty)* | NVD API key for higher rate limits |
| `FEEDS_PATH` | `feeds.json` | Path to feed sources config |

## Getting an NVD API Key

1. Go to https://nvd.nist.gov/developers/request-an-api-key
2. Fill in the form and confirm via email
3. Set `NVD_API_KEY` in your `.env` file
4. This increases NVD rate limits from 5 to 50 requests per 30 seconds

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
