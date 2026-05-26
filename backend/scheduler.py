"""Feed refresh scheduler using APScheduler."""

import os
from apscheduler.schedulers.asyncio import AsyncIOScheduler
import structlog

from backend.fetcher import fetch_all_sources
from backend.enricher import enrich_pending_articles, refresh_kev_catalog

logger = structlog.get_logger()

REFRESH_INTERVAL_MINUTES = int(os.getenv("REFRESH_INTERVAL_MINUTES", "15"))
ENRICHMENT_INTERVAL_MINUTES = int(os.getenv("ENRICHMENT_INTERVAL_MINUTES", "5"))

scheduler = AsyncIOScheduler()


async def scheduled_fetch():
    logger.info("scheduled_fetch_started")
    try:
        results = await fetch_all_sources()
        logger.info("scheduled_fetch_complete", **results)
    except Exception as e:
        logger.error("scheduled_fetch_error", error=str(e))


async def scheduled_enrich():
    try:
        await enrich_pending_articles()
    except Exception as e:
        logger.error("scheduled_enrich_error", error=str(e))


def start_scheduler():
    scheduler.add_job(
        scheduled_fetch,
        "interval",
        minutes=REFRESH_INTERVAL_MINUTES,
        id="feed_refresh",
        replace_existing=True,
    )
    scheduler.add_job(
        scheduled_enrich,
        "interval",
        minutes=ENRICHMENT_INTERVAL_MINUTES,
        id="cve_enrichment",
        replace_existing=True,
    )
    scheduler.add_job(
        refresh_kev_catalog,
        "interval",
        hours=1,
        id="kev_refresh",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(
        "scheduler_started",
        refresh_interval=f"{REFRESH_INTERVAL_MINUTES}m",
        enrichment_interval=f"{ENRICHMENT_INTERVAL_MINUTES}m",
    )


def stop_scheduler():
    scheduler.shutdown(wait=False)
    logger.info("scheduler_stopped")
