"""PoC / CVE enrichment — queries external sources for exploit data."""

import asyncio
import csv
import io
import os
import re
from datetime import datetime, timezone, timedelta

import httpx
import structlog

from backend import db

logger = structlog.get_logger()

USER_AGENT = "CyberNewsAggregator/1.0 (+https://github.com/cybernews-aggregator)"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
ENRICHMENT_TTL_HOURS = int(os.getenv("ENRICHMENT_TTL_HOURS", "6"))

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

# In-memory KEV cache
_kev_cache: dict[str, dict] = {}
_kev_last_fetched: datetime | None = None

# In-memory Exploit-DB CSV cache: maps CVE ID → list of EDB IDs
_exploitdb_cache: dict[str, list[str]] = {}
_exploitdb_last_fetched: datetime | None = None


async def refresh_kev_catalog():
    """Fetch CISA KEV catalog and cache it in memory (refresh every hour)."""
    global _kev_cache, _kev_last_fetched

    if _kev_last_fetched and (datetime.now(timezone.utc) - _kev_last_fetched) < timedelta(hours=1):
        return

    try:
        async with httpx.AsyncClient(
            timeout=30.0, headers={"User-Agent": USER_AGENT}, verify=False
        ) as client:
            resp = await client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            if resp.status_code == 200:
                data = resp.json()
                _kev_cache.clear()
                for vuln in data.get("vulnerabilities", []):
                    cve_id = vuln.get("cveID", "")
                    if cve_id:
                        _kev_cache[cve_id] = {
                            "date_added": vuln.get("dateAdded"),
                            "ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known",
                            "product": vuln.get("product"),
                            "vendor": vuln.get("vendorProject"),
                        }
                _kev_last_fetched = datetime.now(timezone.utc)
                logger.info("kev_catalog_refreshed", count=len(_kev_cache))
    except Exception as e:
        logger.error("kev_catalog_fetch_error", error=str(e))


async def refresh_exploitdb_cache():
    """Fetch Exploit-DB CSV from GitLab mirror and build CVE→EDB-ID index (refresh every 24h)."""
    global _exploitdb_cache, _exploitdb_last_fetched

    if _exploitdb_last_fetched and (datetime.now(timezone.utc) - _exploitdb_last_fetched) < timedelta(hours=24):
        return

    csv_url = (
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    )

    try:
        async with httpx.AsyncClient(
            timeout=60.0, headers={"User-Agent": USER_AGENT}, follow_redirects=True, verify=False
        ) as client:
            resp = await client.get(csv_url)
            if resp.status_code == 200:
                new_cache: dict[str, list[str]] = {}
                reader = csv.DictReader(io.StringIO(resp.text))
                for row in reader:
                    edb_id = row.get("id", "").strip()
                    codes = row.get("codes", "")
                    if not edb_id or not codes:
                        continue
                    for code in codes.split(";"):
                        code = code.strip()
                        if code.startswith("CVE-"):
                            if code not in new_cache:
                                new_cache[code] = []
                            new_cache[code].append(edb_id)

                _exploitdb_cache.clear()
                _exploitdb_cache.update(new_cache)
                _exploitdb_last_fetched = datetime.now(timezone.utc)
                logger.info("exploitdb_cache_refreshed", cve_count=len(_exploitdb_cache))
            else:
                logger.warning("exploitdb_csv_fetch_non_200", status=resp.status_code)
    except Exception as e:
        logger.error("exploitdb_cache_fetch_error", error=str(e))


async def query_github_pocs(cve_id: str) -> list[dict]:
    """Query nomi-sec PoC-in-GitHub API."""
    try:
        async with httpx.AsyncClient(
            timeout=15.0, headers={"User-Agent": USER_AGENT}, verify=False
        ) as client:
            resp = await client.get(
                f"https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve_id}"
            )
            if resp.status_code == 200:
                data = resp.json()
                pocs = []
                for item in data.get("pocs", []):
                    pocs.append({
                        "name": item.get("name", ""),
                        "url": item.get("html_url", ""),
                        "stars": item.get("stargazers_count", 0),
                        "created": item.get("created_at", ""),
                    })
                return pocs
    except Exception as e:
        logger.warning("github_poc_query_error", cve_id=cve_id, error=str(e))
    return []


def query_exploitdb(cve_id: str) -> list[str]:
    """Lookup Exploit-DB IDs for a CVE from the in-memory CSV cache.

    Returns a list of EDB IDs (e.g. ["12345", "67890"]).
    The cache must be populated via refresh_exploitdb_cache() first.
    """
    return _exploitdb_cache.get(cve_id, [])


async def query_sploitus(cve_id: str) -> list[str]:
    """Query Sploitus search API for exploit URLs matching a CVE ID.

    Returns a list of exploit URLs.
    """
    try:
        async with httpx.AsyncClient(
            timeout=15.0, headers={"User-Agent": USER_AGENT}, verify=False
        ) as client:
            resp = await client.post(
                "https://sploitus.com/search",
                json={
                    "type": "exploits",
                    "query": cve_id,
                    "title": False,
                    "sort": "default",
                    "offset": 0,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                urls = []
                for item in data.get("exploits", []):
                    href = item.get("href", "")
                    if href:
                        urls.append(href)
                return urls[:10]  # Limit to 10 most relevant
    except Exception as e:
        logger.warning("sploitus_query_error", cve_id=cve_id, error=str(e))
    return []


async def query_nvd_cvss(cve_id: str) -> dict | None:
    """Query NVD API for CVSS score."""
    headers = {"User-Agent": USER_AGENT}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        async with httpx.AsyncClient(timeout=15.0, headers=headers, verify=False) as client:
            resp = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            )
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_data = vulns[0].get("cve", {})
                    metrics = cve_data.get("metrics", {})

                    # Try CVSS v3.1 first, then v3.0
                    for version in ("cvssMetricV31", "cvssMetricV30"):
                        metric_list = metrics.get(version, [])
                        if metric_list:
                            cvss = metric_list[0].get("cvssData", {})
                            return {
                                "score": cvss.get("baseScore"),
                                "vector": cvss.get("vectorString"),
                            }
            elif resp.status_code == 403:
                logger.warning("nvd_rate_limited", cve_id=cve_id)
    except Exception as e:
        logger.warning("nvd_query_error", cve_id=cve_id, error=str(e))
    return None


def score_to_severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "INFO"


async def enrich_cve(cve_id: str, force: bool = False) -> dict:
    """Enrich a single CVE ID with PoC and vulnerability data."""
    # Check cache
    if not force:
        existing = await db.get_cve_enrichment(cve_id)
        if existing:
            enriched_at = datetime.fromisoformat(existing["enriched_at"])
            if (datetime.now(timezone.utc) - enriched_at.replace(tzinfo=timezone.utc)) < timedelta(
                hours=ENRICHMENT_TTL_HOURS
            ):
                return existing

    await refresh_kev_catalog()
    await refresh_exploitdb_cache()

    # Query sources concurrently
    github_task = asyncio.create_task(query_github_pocs(cve_id))
    nvd_task = asyncio.create_task(query_nvd_cvss(cve_id))
    sploitus_task = asyncio.create_task(query_sploitus(cve_id))

    github_pocs = await github_task
    nvd_data = await nvd_task
    sploitus_urls = await sploitus_task

    # Exploit-DB is a synchronous cache lookup (no await needed)
    exploit_db_ids = query_exploitdb(cve_id)

    kev_info = _kev_cache.get(cve_id, {})

    enrichment = {
        "cve_id": cve_id,
        "github_pocs": github_pocs,
        "is_kev": cve_id in _kev_cache,
        "kev_date_added": kev_info.get("date_added"),
        "kev_ransomware": kev_info.get("ransomware", False),
        "cvss_score": nvd_data.get("score") if nvd_data else None,
        "cvss_vector": nvd_data.get("vector") if nvd_data else None,
        "exploit_db_ids": exploit_db_ids,
        "sploitus_urls": sploitus_urls,
    }

    await db.upsert_cve_enrichment(enrichment)
    logger.info(
        "cve_enriched",
        cve_id=cve_id,
        pocs=len(github_pocs),
        is_kev=enrichment["is_kev"],
        exploitdb=len(exploit_db_ids),
        sploitus=len(sploitus_urls),
    )

    return enrichment


async def enrich_article(article: dict):
    """Enrich an article that has CVE IDs."""
    import json
    cve_ids = article.get("cve_ids", [])
    if isinstance(cve_ids, str):
        cve_ids = json.loads(cve_ids)

    if not cve_ids:
        return

    has_poc = False
    for cve_id in cve_ids:
        try:
            result = await enrich_cve(cve_id)
            if (result.get("github_pocs") or result.get("is_kev")
                    or result.get("exploit_db_ids") or result.get("sploitus_urls")):
                has_poc = True
        except Exception as e:
            logger.warning("article_enrich_error", cve_id=cve_id, error=str(e))

    if has_poc:
        await db.mark_article_enriched(article["id"])


async def enrich_pending_articles():
    """Find articles with CVE IDs that haven't been enriched and enrich them."""
    conn = await db.get_db()
    try:
        cursor = await conn.execute(
            """SELECT id, cve_ids FROM articles
               WHERE cve_ids != '[]' AND is_poc_enriched = 0
               ORDER BY published_at DESC NULLS LAST
               LIMIT 50"""
        )
        rows = await cursor.fetchall()
    finally:
        await db.release_db(conn)

    # Rate-limit NVD queries: 5 req/30s without key, 50 with key
    max_concurrent = 10 if NVD_API_KEY else 2
    sem = asyncio.Semaphore(max_concurrent)

    async def _enrich_one(row):
        async with sem:
            article = dict(row)
            await enrich_article(article)
            await asyncio.sleep(0.5)

    await asyncio.gather(*[_enrich_one(r) for r in rows])

    if rows:
        logger.info("enrichment_batch_complete", count=len(rows))
