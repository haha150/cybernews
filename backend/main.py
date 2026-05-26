"""
CyberNews Aggregator — Backend Entry Point

Language: Python 3.12 + FastAPI
Why: FastAPI provides async-first HTTP handling ideal for concurrent RSS fetching
across 80+ feeds. feedparser is the gold standard for RSS/Atom parsing. Python's
asyncio + httpx give excellent concurrency for I/O-bound enrichment queries.
SQLite via aiosqlite keeps deployment simple (single file, no extra service).
APScheduler handles periodic refresh without external cron or celery.
"""

import asyncio
import json
import os

import structlog
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


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
        await asyncio.sleep(2)  # Brief delay to let server finish startup
        results = await fetch_all_sources()
        logger.info("startup_seed_complete", **results)
    except Exception as e:
        logger.error("startup_seed_error", error=str(e))


@app.on_event("shutdown")
async def shutdown():
    stop_scheduler()
    logger.info("app_stopped")
