"""Database layer — async SQLite via aiosqlite with connection pooling."""

import asyncio
import json
import os
import aiosqlite
import structlog

logger = structlog.get_logger()

DB_PATH = os.getenv("DB_PATH", "/app/data/cybernews.db")
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'news',
    enabled INTEGER NOT NULL DEFAULT 1,
    tags TEXT DEFAULT '[]',
    last_fetched_at TEXT,
    last_status_code INTEGER,
    last_error TEXT,
    article_count INTEGER DEFAULT 0,
    is_custom INTEGER DEFAULT 0,
    consecutive_failures INTEGER DEFAULT 0,
    disabled_at TEXT
);

CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    description TEXT,
    published_at TEXT,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
    source_id TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'news',
    cve_ids TEXT DEFAULT '[]',
    severity TEXT,
    is_poc_enriched INTEGER DEFAULT 0,
    UNIQUE(url),
    FOREIGN KEY (source_id) REFERENCES sources(id)
);

CREATE TABLE IF NOT EXISTS cve_enrichments (
    cve_id TEXT PRIMARY KEY,
    github_pocs TEXT DEFAULT '[]',
    is_kev INTEGER DEFAULT 0,
    kev_date_added TEXT,
    kev_ransomware INTEGER DEFAULT 0,
    cvss_score REAL,
    cvss_vector TEXT,
    exploit_db_ids TEXT DEFAULT '[]',
    sploitus_urls TEXT DEFAULT '[]',
    enriched_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_articles_source ON articles(source_id);
CREATE INDEX IF NOT EXISTS idx_articles_category ON articles(category);
CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_articles_url ON articles(url);
CREATE INDEX IF NOT EXISTS idx_articles_title_source ON articles(title, source_id);
CREATE INDEX IF NOT EXISTS idx_articles_fetched ON articles(fetched_at);
"""

# --- Connection pool ---
_pool: list[aiosqlite.Connection] = []
_pool_lock = asyncio.Lock()
_pool_size = int(os.getenv("DB_POOL_SIZE", "5"))


async def _create_conn() -> aiosqlite.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA foreign_keys=ON")
    await conn.execute("PRAGMA busy_timeout=5000")
    return conn


async def get_db() -> aiosqlite.Connection:
    async with _pool_lock:
        if _pool:
            return _pool.pop()
    return await _create_conn()


async def release_db(conn: aiosqlite.Connection):
    async with _pool_lock:
        if len(_pool) < _pool_size:
            _pool.append(conn)
            return
    await conn.close()


async def close_pool():
    async with _pool_lock:
        for conn in _pool:
            await conn.close()
        _pool.clear()


async def init_db():
    conn = await get_db()
    try:
        await conn.executescript(SCHEMA)
        await conn.commit()
        # Migrate: add columns if missing (existing installs)
        for col, defn in [
            ("consecutive_failures", "INTEGER DEFAULT 0"),
            ("disabled_at", "TEXT"),
        ]:
            try:
                await conn.execute(f"ALTER TABLE sources ADD COLUMN {col} {defn}")
                await conn.commit()
            except Exception:
                pass  # Column already exists
        logger.info("database_initialized", path=DB_PATH)
    finally:
        await release_db(conn)


async def seed_sources(sources: list[dict]):
    conn = await get_db()
    try:
        for src in sources:
            await conn.execute(
                """INSERT OR IGNORE INTO sources (id, name, url, category, enabled, tags, is_custom)
                   VALUES (?, ?, ?, ?, ?, ?, 0)""",
                (src["id"], src["name"], src["url"], src["category"],
                 1 if src.get("enabled", True) else 0, json.dumps(src.get("tags", []))),
            )
        await conn.commit()
        logger.info("sources_seeded", count=len(sources))
    finally:
        await release_db(conn)


async def get_enabled_sources() -> list[dict]:
    conn = await get_db()
    try:
        cursor = await conn.execute("SELECT * FROM sources WHERE enabled = 1")
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await release_db(conn)


async def get_all_sources() -> list[dict]:
    conn = await get_db()
    try:
        cursor = await conn.execute("SELECT * FROM sources ORDER BY category, name")
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await release_db(conn)


async def update_source_health(source_id: str, status_code: int | None, error: str | None):
    conn = await get_db()
    try:
        if error or (status_code and status_code >= 400):
            # Increment failure counter
            await conn.execute(
                """UPDATE sources SET last_fetched_at = datetime('now'),
                   last_status_code = ?, last_error = ?,
                   consecutive_failures = consecutive_failures + 1
                   WHERE id = ?""",
                (status_code, error, source_id),
            )
            await conn.commit()
            # Auto-disable after 10 consecutive failures
            await conn.execute(
                """UPDATE sources SET enabled = 0, disabled_at = datetime('now')
                   WHERE id = ? AND consecutive_failures >= 10 AND enabled = 1""",
                (source_id,),
            )
            await conn.commit()
            cursor = await conn.execute(
                "SELECT consecutive_failures, enabled FROM sources WHERE id = ?", (source_id,))
            row = await cursor.fetchone()
            if row and row["enabled"] == 0 and row["consecutive_failures"] >= 10:
                logger.warning("source_auto_disabled", source=source_id,
                               failures=row["consecutive_failures"])
        else:
            # Success — reset failure counter
            await conn.execute(
                """UPDATE sources SET last_fetched_at = datetime('now'),
                   last_status_code = ?, last_error = NULL,
                   consecutive_failures = 0
                   WHERE id = ?""",
                (status_code, source_id),
            )
            await conn.commit()
    finally:
        await release_db(conn)


async def update_source_article_count(source_id: str):
    conn = await get_db()
    try:
        await conn.execute(
            """UPDATE sources SET article_count = (
                 SELECT COUNT(*) FROM articles WHERE source_id = ?
               ) WHERE id = ?""", (source_id, source_id))
        await conn.commit()
    finally:
        await release_db(conn)


async def insert_article(article: dict) -> bool:
    conn = await get_db()
    try:
        # Title+source dedup
        cursor = await conn.execute(
            "SELECT 1 FROM articles WHERE title = ? AND source_id = ? LIMIT 1",
            (article["title"], article["source_id"]),
        )
        if await cursor.fetchone():
            return False
        try:
            await conn.execute(
                """INSERT INTO articles (title, url, description, published_at, source_id, category, cve_ids, severity)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (article["title"], article["url"], article.get("description"),
                 article.get("published_at"), article["source_id"],
                 article.get("category", "news"), json.dumps(article.get("cve_ids", [])),
                 article.get("severity")),
            )
            await conn.commit()
            return True
        except aiosqlite.IntegrityError:
            return False
    finally:
        await release_db(conn)


async def get_articles(category=None, search=None, poc_only=False, page=1, limit=50):
    conn = await get_db()
    try:
        conditions, params = [], []
        if category and category != "all":
            cat_map = {"cve":"cve","redteam":"redteam","threat-intel":"threat-intel",
                       "news":"news","government":"government","research":"research","zero-day":"cve"}
            conditions.append("a.category = ?")
            params.append(cat_map.get(category, category))
        if search:
            conditions.append("(a.title LIKE ? OR a.description LIKE ?)")
            term = f"%{search}%"
            params.extend([term, term])
        if poc_only:
            conditions.append("a.is_poc_enriched = 1")

        where = " AND ".join(conditions) if conditions else "1=1"
        cursor = await conn.execute(f"SELECT COUNT(*) FROM articles a WHERE {where}", params)
        total = (await cursor.fetchone())[0]

        offset = (page - 1) * limit
        cursor = await conn.execute(f"""
            SELECT a.*, s.name as source_name FROM articles a
            LEFT JOIN sources s ON a.source_id = s.id
            WHERE {where}
            ORDER BY a.published_at DESC NULLS LAST, a.fetched_at DESC
            LIMIT ? OFFSET ?""", params + [limit, offset])
        articles = []
        for r in await cursor.fetchall():
            art = dict(r)
            art["cve_ids"] = json.loads(art.get("cve_ids") or "[]")
            articles.append(art)
        return articles, total
    finally:
        await release_db(conn)


async def get_cve_enrichment(cve_id: str):
    conn = await get_db()
    try:
        cursor = await conn.execute("SELECT * FROM cve_enrichments WHERE cve_id = ?", (cve_id,))
        row = await cursor.fetchone()
        if row:
            d = dict(row)
            for k in ("github_pocs", "exploit_db_ids", "sploitus_urls"):
                d[k] = json.loads(d.get(k) or "[]")
            return d
        return None
    finally:
        await release_db(conn)


async def upsert_cve_enrichment(data: dict):
    conn = await get_db()
    try:
        await conn.execute(
            """INSERT INTO cve_enrichments (cve_id, github_pocs, is_kev, kev_date_added,
                   kev_ransomware, cvss_score, cvss_vector, exploit_db_ids, sploitus_urls, enriched_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(cve_id) DO UPDATE SET
                   github_pocs=excluded.github_pocs, is_kev=excluded.is_kev,
                   kev_date_added=excluded.kev_date_added, kev_ransomware=excluded.kev_ransomware,
                   cvss_score=excluded.cvss_score, cvss_vector=excluded.cvss_vector,
                   exploit_db_ids=excluded.exploit_db_ids, sploitus_urls=excluded.sploitus_urls,
                   enriched_at=datetime('now')""",
            (data["cve_id"], json.dumps(data.get("github_pocs", [])),
             1 if data.get("is_kev") else 0, data.get("kev_date_added"),
             1 if data.get("kev_ransomware") else 0, data.get("cvss_score"),
             data.get("cvss_vector"), json.dumps(data.get("exploit_db_ids", [])),
             json.dumps(data.get("sploitus_urls", []))),
        )
        await conn.commit()
    finally:
        await release_db(conn)


async def mark_article_enriched(article_id: int):
    conn = await get_db()
    try:
        await conn.execute("UPDATE articles SET is_poc_enriched = 1 WHERE id = ?", (article_id,))
        await conn.commit()
    finally:
        await release_db(conn)


async def get_stats():
    conn = await get_db()
    try:
        c = await conn.execute("SELECT COUNT(*) FROM articles")
        total_articles = (await c.fetchone())[0]
        c = await conn.execute("SELECT COUNT(*) FROM sources")
        total_sources = (await c.fetchone())[0]
        c = await conn.execute("SELECT COUNT(DISTINCT cve_id) FROM cve_enrichments")
        total_cves = (await c.fetchone())[0]
        c = await conn.execute("SELECT COUNT(*) FROM cve_enrichments WHERE github_pocs != '[]'")
        total_pocs = (await c.fetchone())[0]
        return {"total_articles": total_articles, "total_sources": total_sources,
                "cves_tracked": total_cves, "pocs_found": total_pocs}
    finally:
        await release_db(conn)


async def add_custom_source(name: str, url: str, category: str):
    import hashlib
    source_id = "custom_" + hashlib.sha256(url.encode()).hexdigest()[:12]
    conn = await get_db()
    try:
        await conn.execute(
            """INSERT INTO sources (id, name, url, category, enabled, tags, is_custom)
               VALUES (?, ?, ?, ?, 1, '[]', 1)""",
            (source_id, name, url, category))
        await conn.commit()
        cursor = await conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,))
        return dict(await cursor.fetchone())
    finally:
        await release_db(conn)


async def update_source(source_id: str, updates: dict):
    conn = await get_db()
    try:
        allowed = {"name", "enabled", "category"}
        sets, params = [], []
        for k, v in updates.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                params.append(v)
        if not sets:
            return
        params.append(source_id)
        await conn.execute(f"UPDATE sources SET {', '.join(sets)} WHERE id = ?", params)
        await conn.commit()
    finally:
        await release_db(conn)


async def delete_source(source_id: str) -> bool:
    conn = await get_db()
    try:
        cursor = await conn.execute("DELETE FROM sources WHERE id = ? AND is_custom = 1", (source_id,))
        await conn.commit()
        return cursor.rowcount > 0
    finally:
        await release_db(conn)


async def get_enrichments_for_cves(cve_ids: list[str]) -> dict:
    if not cve_ids:
        return {}
    conn = await get_db()
    try:
        placeholders = ",".join("?" for _ in cve_ids)
        cursor = await conn.execute(
            f"SELECT * FROM cve_enrichments WHERE cve_id IN ({placeholders})", cve_ids)
        result = {}
        for r in await cursor.fetchall():
            d = dict(r)
            for k in ("github_pocs", "exploit_db_ids", "sploitus_urls"):
                d[k] = json.loads(d.get(k) or "[]")
            result[d["cve_id"]] = d
        return result
    finally:
        await release_db(conn)


async def cleanup_old_articles():
    """Delete articles older than RETENTION_DAYS and vacuum."""
    conn = await get_db()
    try:
        cursor = await conn.execute(
            "DELETE FROM articles WHERE fetched_at < datetime('now', ?)",
            (f"-{RETENTION_DAYS} days",))
        deleted = cursor.rowcount
        if deleted > 0:
            await conn.commit()
            await conn.execute(
                """UPDATE sources SET article_count = (
                     SELECT COUNT(*) FROM articles WHERE articles.source_id = sources.id)""")
            await conn.commit()
            logger.info("cleanup_old_articles", deleted=deleted, retention_days=RETENTION_DAYS)
        await conn.execute("PRAGMA incremental_vacuum")
    finally:
        await release_db(conn)


async def retry_disabled_sources():
    """Re-enable sources that were auto-disabled more than 24h ago for a retry."""
    conn = await get_db()
    try:
        cursor = await conn.execute(
            """UPDATE sources SET enabled = 1, consecutive_failures = 0, disabled_at = NULL
               WHERE enabled = 0 AND disabled_at IS NOT NULL
               AND disabled_at < datetime('now', '-1 day')
               RETURNING id, name""")
        rows = await cursor.fetchall()
        if rows:
            await conn.commit()
            for r in rows:
                logger.info("source_auto_reenabled", source=r["id"], name=r["name"])
    finally:
        await release_db(conn)
