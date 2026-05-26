"""
CyberNews Aggregator — Backend Entry Point

Language: Python 3.12 + FastAPI
"""

import asyncio
import json
import os
import secrets
import time
from collections import defaultdict

import structlog
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from backend import db
from backend.fetcher import fetch_all_sources
from backend.routes import router
from backend.scheduler import start_scheduler, stop_scheduler

load_dotenv()

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

logger = structlog.get_logger()

app = FastAPI(title="CyberNews Aggregator", version="1.0.0")

# --- GZip ---
app.add_middleware(GZipMiddleware, minimum_size=500)

# --- CORS ---
cors_origins = os.getenv("CORS_ORIGINS", "").strip()
if cors_origins:
    origins = [o.strip() for o in cors_origins.split(",") if o.strip()]
else:
    origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Optional Basic Auth ---
AUTH_USERNAME = os.getenv("AUTH_USERNAME", "").strip()
AUTH_PASSWORD = os.getenv("AUTH_PASSWORD", "").strip()
security = HTTPBasic(auto_error=False)


async def check_auth(request: Request):
    """If AUTH_USERNAME/AUTH_PASSWORD are set, enforce HTTP Basic Auth."""
    if not AUTH_USERNAME or not AUTH_PASSWORD:
        return  # Auth not configured — allow all

    # Allow healthcheck endpoint without auth
    if request.url.path == "/api/stats":
        return

    credentials: HTTPBasicCredentials | None = await security(request)
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )
    correct_user = secrets.compare_digest(credentials.username.encode(), AUTH_USERNAME.encode())
    correct_pass = secrets.compare_digest(credentials.password.encode(), AUTH_PASSWORD.encode())
    if not (correct_user and correct_pass):
        _record_failed_login(request)
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

# --- Fail2ban: block IPs after repeated failed logins ---
_fail_store: dict[str, list[float]] = defaultdict(list)
_banned_ips: dict[str, float] = {}
FAIL2BAN_MAX_ATTEMPTS = int(os.getenv("FAIL2BAN_MAX_ATTEMPTS", "5"))
FAIL2BAN_WINDOW = int(os.getenv("FAIL2BAN_WINDOW", "300"))      # 5 min window
FAIL2BAN_BAN_TIME = int(os.getenv("FAIL2BAN_BAN_TIME", "900"))  # 15 min ban


def _record_failed_login(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    _fail_store[client_ip].append(now)
    # Clean old attempts outside window
    _fail_store[client_ip] = [t for t in _fail_store[client_ip] if now - t < FAIL2BAN_WINDOW]
    if len(_fail_store[client_ip]) >= FAIL2BAN_MAX_ATTEMPTS:
        _banned_ips[client_ip] = now
        _fail_store[client_ip].clear()
        logger.warning("fail2ban_ip_banned", ip=client_ip, ban_seconds=FAIL2BAN_BAN_TIME)


# --- Simple in-memory rate limiter ---
_rate_store: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_RPM", "30"))  # requests per minute


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"

    # Fail2ban check — block banned IPs
    if client_ip in _banned_ips:
        banned_at = _banned_ips[client_ip]
        if time.time() - banned_at < FAIL2BAN_BAN_TIME:
            return JSONResponse(
                status_code=403,
                content={"detail": "IP temporarily banned due to repeated failed login attempts."},
            )
        else:
            del _banned_ips[client_ip]

    # Rate limit mutating endpoints
    if request.url.path in ("/api/refresh",) and request.method == "POST":
        now = time.time()
        window = 60.0

        # Clean old entries
        _rate_store[client_ip] = [t for t in _rate_store[client_ip] if now - t < window]

        if len(_rate_store[client_ip]) >= RATE_LIMIT_RPM:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Try again later."},
            )
        _rate_store[client_ip].append(now)

    return await call_next(request)


app.include_router(router, dependencies=[Depends(check_auth)])


@app.on_event("startup")
async def startup():
    logger.info("app_starting")

    # Init database
    await db.init_db()

    # Seed sources from feeds.json
    feeds_path = os.getenv("FEEDS_PATH", "feeds.json")
    try:
        with open(feeds_path, "r") as f:
            config = json.load(f)
        await db.seed_sources(config.get("sources", []))
    except FileNotFoundError:
        logger.error("feeds_json_not_found", path=feeds_path)

    # Startup seed: immediate full refresh so dashboard isn't empty
    logger.info("startup_seed_starting")
    asyncio.create_task(_startup_seed())

    # Start scheduler
    start_scheduler()


async def _startup_seed():
    """Run initial fetch in background so the server starts responding immediately."""
    try:
        await asyncio.sleep(2)
        results = await fetch_all_sources()
        logger.info("startup_seed_complete", **results)
    except Exception as e:
        logger.error("startup_seed_error", error=str(e))


@app.on_event("shutdown")
async def shutdown():
    stop_scheduler()
    await db.close_pool()
    logger.info("app_stopped")
