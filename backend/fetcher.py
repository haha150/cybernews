"""RSS/Atom feed fetcher and parser."""

import asyncio
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import feedparser
import httpx
import structlog

from backend import db

logger = structlog.get_logger()

USER_AGENT = "CyberNewsAggregator/1.0 (+https://github.com/cybernews-aggregator)"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

SEVERITY_KEYWORDS = {
    "critical": "CRITICAL",
    "remote code execution": "CRITICAL",
    "rce": "CRITICAL",
    "zero-day": "CRITICAL",
    "0-day": "CRITICAL",
    "high": "HIGH",
    "privilege escalation": "HIGH",
    "authentication bypass": "HIGH",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
}


def detect_severity(title: str, description: str) -> str | None:
    text = f"{title} {description}".lower()
    for keyword, level in SEVERITY_KEYWORDS.items():
        if keyword in text:
            return level
    return None


def parse_published(entry) -> str | None:
    for field in ("published_parsed", "updated_parsed"):
        parsed = getattr(entry, field, None) or entry.get(field)
        if parsed:
            try:
                dt = datetime(*parsed[:6], tzinfo=timezone.utc)
                return dt.isoformat()
            except Exception:
                pass
    for field in ("published", "updated"):
        raw = getattr(entry, field, None) or entry.get(field)
        if raw:
            try:
                dt = parsedate_to_datetime(raw)
                return dt.isoformat()
            except Exception:
                try:
                    dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    return dt.isoformat()
                except Exception:
                    pass
    return None


def extract_description(entry) -> str:
    desc = ""
    if hasattr(entry, "summary"):
        desc = entry.summary or ""
    elif hasattr(entry, "description"):
        desc = entry.description or ""
    # Strip HTML tags simply
    desc = re.sub(r"<[^>]+>", "", desc)
    desc = re.sub(r"\s+", " ", desc).strip()
    if len(desc) > 1000:
        desc = desc[:1000] + "..."
    return desc


async def fetch_source(source: dict) -> int:
    source_id = source["id"]
    url = source["url"]
    category = source["category"]
    new_count = 0

    try:
        async with httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            resp = await client.get(url)
            status = resp.status_code
            await db.update_source_health(source_id, status, None)

            if status != 200:
                logger.warning("feed_fetch_non_200", source=source_id, status=status)
                return 0

            feed = feedparser.parse(resp.text)

            for entry in feed.entries:
                link = getattr(entry, "link", None) or ""
                title = getattr(entry, "title", None) or ""
                if not link or not title:
                    continue

                description = extract_description(entry)
                published = parse_published(entry)
                text = f"{title} {description}"
                cve_ids = list(set(CVE_PATTERN.findall(text)))
                severity = detect_severity(title, description)

                # Override category for zero-day content
                art_category = category
                if any(kw in text.lower() for kw in ("zero-day", "0-day", "zero day")):
                    art_category = "cve"

                article = {
                    "title": title.strip(),
                    "url": link.strip(),
                    "description": description,
                    "published_at": published,
                    "source_id": source_id,
                    "category": art_category,
                    "cve_ids": cve_ids,
                    "severity": severity,
                }

                inserted = await db.insert_article(article)
                if inserted:
                    new_count += 1

            await db.update_source_article_count(source_id)
            logger.info("feed_fetched", source=source_id, new_articles=new_count, total_entries=len(feed.entries))

    except Exception as e:
        await db.update_source_health(source_id, None, str(e))
        logger.error("feed_fetch_error", source=source_id, error=str(e))

    return new_count


async def fetch_all_sources() -> dict:
    sources = await db.get_enabled_sources()
    results = {"sources_fetched": 0, "new_articles": 0, "errors": 0}

    sem = asyncio.Semaphore(10)

    async def _fetch_one(source):
        async with sem:
            try:
                new = await fetch_source(source)
                results["sources_fetched"] += 1
                results["new_articles"] += new
            except Exception as e:
                results["errors"] += 1
                logger.error("source_fetch_failed", source=source["id"], error=str(e))

    await asyncio.gather(*[_fetch_one(s) for s in sources])
    logger.info("fetch_all_complete", **results)
    return results


async def discover_feed_url(url: str) -> str | None:
    """Try to auto-detect an RSS/Atom feed URL from a website URL."""
    common_paths = ["/feed", "/rss", "/rss.xml", "/atom.xml", "/feed.xml", "/feeds", "/blog/feed"]

    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None

            content_type = resp.headers.get("content-type", "")
            if "xml" in content_type or "rss" in content_type or "atom" in content_type:
                return url

            # Parse HTML for <link rel="alternate"> feed references
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "lxml")
            for link_tag in soup.find_all("link", rel="alternate"):
                href = link_tag.get("href", "")
                link_type = link_tag.get("type", "")
                if "rss" in link_type or "atom" in link_type or "xml" in link_type:
                    if href.startswith("/"):
                        from urllib.parse import urljoin
                        href = urljoin(url, href)
                    return href

            # Try common paths
            from urllib.parse import urljoin
            for path in common_paths:
                test_url = urljoin(url, path)
                try:
                    r = await client.get(test_url)
                    ct = r.headers.get("content-type", "")
                    if r.status_code == 200 and ("xml" in ct or "rss" in ct or "atom" in ct):
                        return test_url
                except Exception:
                    continue

    except Exception as e:
        logger.warning("feed_discovery_failed", url=url, error=str(e))

    return None
