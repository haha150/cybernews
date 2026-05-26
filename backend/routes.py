"""API routes for the cybersecurity news aggregator."""

import json
import re
from xml.etree.ElementTree import Element, SubElement, tostring

import httpx
import structlog
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from backend import db
from backend.fetcher import fetch_all_sources, discover_feed_url, USER_AGENT
from backend.enricher import enrich_cve

logger = structlog.get_logger()
router = APIRouter(prefix="/api")


@router.get("/articles")
async def list_articles(
    category: str | None = Query(None),
    search: str | None = Query(None),
    poc_only: bool = Query(False),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
):
    articles, total = await db.get_articles(
        category=category, search=search, poc_only=poc_only, page=page, limit=limit
    )

    # Attach enrichment data to articles with CVE IDs
    all_cves = set()
    for a in articles:
        for cve in a.get("cve_ids", []):
            all_cves.add(cve)

    enrichments = await db.get_enrichments_for_cves(list(all_cves))

    for a in articles:
        a["enrichments"] = {}
        for cve in a.get("cve_ids", []):
            if cve in enrichments:
                a["enrichments"][cve] = enrichments[cve]

    return {
        "articles": articles,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit if limit > 0 else 0,
    }


@router.get("/sources")
async def list_sources():
    sources = await db.get_all_sources()
    for s in sources:
        if isinstance(s.get("tags"), str):
            s["tags"] = json.loads(s["tags"])
    return {"sources": sources}


@router.post("/sources")
async def add_source(body: dict):
    url = body.get("url", "").strip()
    name = body.get("name", "").strip()
    category = body.get("category", "news").strip()

    if not url:
        raise HTTPException(400, "URL is required")
    if not name:
        raise HTTPException(400, "Name is required")

    # Try to discover feed URL if it's a website
    feed_url = await discover_feed_url(url)
    if feed_url:
        url = feed_url

    source = await db.add_custom_source(name, url, category)
    return {"source": source}


@router.put("/sources/{source_id}")
async def update_source(source_id: str, body: dict):
    await db.update_source(source_id, body)
    return {"ok": True}


@router.delete("/sources/{source_id}")
async def delete_source(source_id: str):
    deleted = await db.delete_source(source_id)
    if not deleted:
        raise HTTPException(404, "Source not found or is a built-in source")
    return {"ok": True}


@router.post("/refresh")
async def manual_refresh():
    results = await fetch_all_sources()
    return results


@router.get("/cve/{cve_id}/poc")
async def get_cve_poc(cve_id: str):
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        raise HTTPException(400, "Invalid CVE ID format")
    enrichment = await enrich_cve(cve_id)
    return enrichment


@router.get("/stats")
async def get_stats():
    return await db.get_stats()


@router.get("/opml")
async def export_opml():
    sources = await db.get_all_sources()

    opml = Element("opml", version="2.0")
    head = SubElement(opml, "head")
    title = SubElement(head, "title")
    title.text = "CyberNews Aggregator Feeds"

    body = SubElement(opml, "body")

    categories: dict[str, Element] = {}
    for src in sources:
        cat = src.get("category", "news")
        if cat not in categories:
            outline = SubElement(body, "outline", text=cat, title=cat)
            categories[cat] = outline

        SubElement(
            categories[cat],
            "outline",
            type="rss",
            text=src["name"],
            title=src["name"],
            xmlUrl=src["url"],
        )

    xml_bytes = tostring(opml, encoding="unicode", xml_declaration=True)
    return Response(
        content=xml_bytes,
        media_type="application/xml",
        headers={"Content-Disposition": "attachment; filename=cybernews_feeds.opml"},
    )


@router.get("/discover")
async def discover_sources():
    """Fetch curated GitHub lists and return discovered feed URLs."""
    with open("feeds.json", "r") as f:
        config = json.load(f)

    discovery_urls = config.get("discovery_sources", [])
    discovered = []

    async with httpx.AsyncClient(
        timeout=20.0,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
        verify=False,
    ) as client:
        for url in discovery_urls:
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    continue

                text = resp.text

                if url.endswith(".opml"):
                    # Parse OPML
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(text)
                    for outline in root.iter("outline"):
                        xml_url = outline.get("xmlUrl")
                        if xml_url:
                            discovered.append({
                                "name": outline.get("title") or outline.get("text", "Unknown"),
                                "url": xml_url,
                                "source": url,
                            })
                elif url.endswith(".json"):
                    # Parse JSON
                    data = resp.json()
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict) and item.get("url"):
                                discovered.append({
                                    "name": item.get("name", item.get("title", "Unknown")),
                                    "url": item["url"],
                                    "source": url,
                                })
                else:
                    # Parse Markdown — extract URLs
                    feed_urls = re.findall(
                        r'https?://[^\s\)\]"\'<>]+(?:rss|feed|atom|xml)[^\s\)\]"\'<>]*',
                        text,
                        re.IGNORECASE,
                    )
                    for feed_url in feed_urls:
                        # Clean trailing punctuation
                        feed_url = feed_url.rstrip(".,;:)")
                        discovered.append({
                            "name": "",
                            "url": feed_url,
                            "source": url,
                        })

            except Exception as e:
                logger.warning("discovery_source_error", url=url, error=str(e))

    # Deduplicate by URL
    seen = set()
    unique = []
    existing = await db.get_all_sources()
    existing_urls = {s["url"] for s in existing}
    for item in discovered:
        if item["url"] not in seen and item["url"] not in existing_urls:
            seen.add(item["url"])
            unique.append(item)

    return {"discovered": unique, "count": len(unique)}
