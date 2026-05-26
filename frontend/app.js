/* CyberNews Aggregator — Frontend Application */

const API_BASE = '/api';
let currentCategory = 'all';
let currentPage = 1;
let currentSearch = '';
let pocOnly = false;
let lastArticleCount = 0;
let searchDebounceTimer = null;

// --- Utility ---

function relativeTime(dateStr) {
    if (!dateStr) return '';
    // DB stores UTC — append Z if no timezone indicator present
    if (!dateStr.endsWith('Z') && !dateStr.includes('+') && !dateStr.includes('T')) {
        dateStr = dateStr.replace(' ', 'T') + 'Z';
    } else if (!dateStr.endsWith('Z') && !dateStr.includes('+')) {
        dateStr = dateStr + 'Z';
    }
    const date = new Date(dateStr);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return date.toLocaleDateString();
}

function escapeHtml(text) {
    const el = document.createElement('div');
    el.textContent = text || '';
    return el.innerHTML;
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}

async function apiFetch(path, options = {}) {
    try {
        const resp = await fetch(`${API_BASE}${path}`, {
            headers: { 'Content-Type': 'application/json' },
            ...options,
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const contentType = resp.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await resp.json();
        }
        return await resp.text();
    } catch (err) {
        console.error(`API error: ${path}`, err);
        throw err;
    }
}

// --- Favicon ---

function faviconUrl(articleUrl) {
    try {
        const u = new URL(articleUrl);
        return `https://www.google.com/s2/favicons?domain=${u.hostname}&sz=32`;
    } catch {
        return '';
    }
}

// --- Rendering ---

function renderSkeletons(count = 12) {
    const grid = document.getElementById('article-grid');
    grid.innerHTML = '';
    for (let i = 0; i < count; i++) {
        grid.innerHTML += `
            <div class="skeleton-card">
                <div class="skeleton skeleton-line-short"></div>
                <div class="skeleton skeleton-title"></div>
                <div class="skeleton skeleton-line"></div>
                <div class="skeleton skeleton-line"></div>
                <div class="skeleton skeleton-badge"></div>
            </div>`;
    }
}

function categoryClass(cat) {
    const map = {
        news: 'cat-news',
        cve: 'cat-cve',
        redteam: 'cat-redteam',
        'threat-intel': 'cat-threat-intel',
        government: 'cat-government',
        research: 'cat-research',
    };
    return map[cat] || 'cat-news';
}

function categoryLabel(cat) {
    const map = {
        news: 'News',
        cve: 'CVE',
        redteam: 'Red Team',
        'threat-intel': 'Threat Intel',
        government: 'Government',
        research: 'Research',
    };
    return map[cat] || cat;
}

function renderPocBadges(enrichments) {
    if (!enrichments || Object.keys(enrichments).length === 0) return '';

    let badges = [];
    for (const [cveId, data] of Object.entries(enrichments)) {
        if (data.github_pocs && data.github_pocs.length > 0) {
            const firstPoc = data.github_pocs[0];
            const url = firstPoc.url || '#';
            const count = data.github_pocs.length;
            badges.push(
                `<a href="${escapeHtml(url)}" target="_blank" rel="noopener" class="poc-badge poc-github" title="${count} PoC(s) on GitHub for ${cveId}">🔴 PoC on GitHub (${count})</a>`
            );
        }
        if (data.exploit_db_ids && data.exploit_db_ids.length > 0) {
            badges.push(
                `<span class="poc-badge poc-exploitdb" title="Exploit-DB entries for ${cveId}">🟠 Exploit-DB</span>`
            );
        }
        if (data.is_kev) {
            if (data.kev_ransomware) {
                badges.push(
                    `<span class="poc-badge poc-kev-ransomware" title="CISA KEV + Ransomware! Added: ${data.kev_date_added || 'N/A'}">💀 KEV + Ransomware</span>`
                );
            } else {
                badges.push(
                    `<span class="poc-badge poc-kev" title="CISA Known Exploited Vulnerability. Added: ${data.kev_date_added || 'N/A'}">⚠️ CISA KEV</span>`
                );
            }
        }
        if (data.cvss_score != null) {
            const sev = cvssToSeverity(data.cvss_score);
            badges.push(
                `<span class="poc-badge severity-badge severity-${sev}" title="CVSS: ${data.cvss_score} ${data.cvss_vector || ''}">CVSS ${data.cvss_score}</span>`
            );
        }
    }

    return badges.length > 0 ? `<div class="poc-badges">${badges.join('')}</div>` : '';
}

function cvssToSeverity(score) {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score >= 0.1) return 'LOW';
    return 'INFO';
}

function renderArticleCard(article) {
    const favicon = faviconUrl(article.url);
    const time = relativeTime(article.published_at);
    const sourceName = article.source_name || article.source_id || '';
    const cveIds = article.cve_ids || [];
    const severity = article.severity;
    const enrichments = article.enrichments || {};

    let severityHtml = '';
    if (severity) {
        severityHtml = `<span class="severity-badge severity-${severity}">${severity}</span>`;
    }

    let cveHtml = '';
    if (cveIds.length > 0) {
        cveHtml = `<div class="cve-list">${cveIds.map(c => `<span class="cve-tag">${escapeHtml(c)}</span>`).join('')}</div>`;
    }

    const pocHtml = renderPocBadges(enrichments);

    return `
        <article class="article-card">
            <div class="card-header">
                <img class="source-favicon" src="${escapeHtml(favicon)}" alt="" onerror="this.style.display='none'" loading="lazy">
                <span class="card-source-name">${escapeHtml(sourceName)}</span>
                <span class="card-category ${categoryClass(article.category)}">${categoryLabel(article.category)}</span>
                <span class="card-time">${escapeHtml(time)}</span>
            </div>
            <div class="card-title">
                <a href="${escapeHtml(article.url)}" target="_blank" rel="noopener">${escapeHtml(article.title)}</a>
            </div>
            <div class="card-description">${escapeHtml(article.description || '')}</div>
            ${severityHtml}
            ${cveHtml}
            ${pocHtml}
            <div class="card-footer">
                <a href="${escapeHtml(article.url)}" target="_blank" rel="noopener" class="read-more">Read more →</a>
            </div>
        </article>`;
}

function renderArticles(articles) {
    const grid = document.getElementById('article-grid');
    const emptyState = document.getElementById('empty-state');

    if (articles.length === 0) {
        grid.innerHTML = '';
        emptyState.classList.remove('hidden');
        const emptyMsg = document.getElementById('empty-message');
        if (currentSearch) {
            emptyMsg.textContent = `No results for "${currentSearch}". Try a different search term.`;
        } else if (currentCategory !== 'all') {
            emptyMsg.textContent = `No articles in this category yet. Check back soon!`;
        } else {
            emptyMsg.textContent = 'No articles loaded yet. Click refresh to fetch feeds.';
        }
        return;
    }

    emptyState.classList.add('hidden');
    grid.innerHTML = articles.map(renderArticleCard).join('');
}

function renderPagination(total, page, limit, pages) {
    const paginationEl = document.getElementById('pagination');
    const prevBtn = document.getElementById('prev-page');
    const nextBtn = document.getElementById('next-page');
    const pageInfo = document.getElementById('page-info');

    if (pages <= 1) {
        paginationEl.classList.add('hidden');
        return;
    }

    paginationEl.classList.remove('hidden');
    pageInfo.textContent = `Page ${page} of ${pages}`;
    prevBtn.disabled = page <= 1;
    nextBtn.disabled = page >= pages;
}

// --- Data Fetching ---

async function fetchArticles() {
    renderSkeletons();

    try {
        const params = new URLSearchParams();
        if (currentCategory !== 'all') params.set('category', currentCategory);
        if (currentSearch) params.set('search', currentSearch);
        if (pocOnly) params.set('poc_only', 'true');
        params.set('page', currentPage);
        params.set('limit', 50);

        const data = await apiFetch(`/articles?${params}`);
        renderArticles(data.articles);
        renderPagination(data.total, data.page, data.limit, data.pages);

        // Toast on new articles
        if (lastArticleCount > 0 && data.total > lastArticleCount) {
            const newCount = data.total - lastArticleCount;
            showToast(`${newCount} new article${newCount > 1 ? 's' : ''} found!`, 'success');
        }
        lastArticleCount = data.total;
    } catch (err) {
        showToast('Failed to load articles', 'error');
        document.getElementById('article-grid').innerHTML = '';
        document.getElementById('empty-state').classList.remove('hidden');
    }
}

async function fetchStats() {
    try {
        const stats = await apiFetch('/stats');
        document.getElementById('stats-articles').textContent = `${stats.total_articles} articles`;
        document.getElementById('stats-sources').textContent = `${stats.total_sources} sources`;
        document.getElementById('stats-cves').textContent = `${stats.cves_tracked} CVEs`;
        document.getElementById('last-updated').textContent = `Updated: ${new Date().toLocaleTimeString()}`;
    } catch {
        // Silent fail
    }
}

async function fetchSources() {
    try {
        const data = await apiFetch('/sources');
        renderSourceList(data.sources);
        renderSourceTable(data.sources);
        updateCategoryCounts(data.sources);
    } catch {
        // Silent fail
    }
}

function renderSourceList(sources) {
    const list = document.getElementById('source-list');
    list.innerHTML = sources.map(s => {
        let dotClass = 'healthy';
        if (s.last_error) dotClass = 'error';
        else if (s.last_status_code && s.last_status_code !== 200) dotClass = 'warning';
        else if (!s.last_fetched_at) dotClass = 'warning';

        return `
            <div class="source-item" title="${escapeHtml(s.url)}">
                <span class="source-dot ${dotClass}"></span>
                <span class="source-name">${escapeHtml(s.name)}</span>
                <span class="source-count-badge">${s.article_count || 0}</span>
            </div>`;
    }).join('');
}

function updateCategoryCounts(sources) {
    const counts = {};
    let total = 0;
    for (const s of sources) {
        const count = s.article_count || 0;
        counts[s.category] = (counts[s.category] || 0) + count;
        total += count;
    }
    const countEl = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };
    countEl('count-all', total);
    countEl('count-cve', counts['cve'] || 0);
    countEl('count-redteam', counts['redteam'] || 0);
    countEl('count-threat-intel', counts['threat-intel'] || 0);
    countEl('count-news', counts['news'] || 0);
    countEl('count-government', counts['government'] || 0);
    countEl('count-research', counts['research'] || 0);
}

function renderSourceTable(sources) {
    const tbody = document.getElementById('source-table-body');
    tbody.innerHTML = sources.map(s => {
        let statusDot = '🟢';
        if (s.last_error) statusDot = '🔴';
        else if (s.last_status_code && s.last_status_code !== 200) statusDot = '🟡';
        else if (!s.last_fetched_at) statusDot = '⚪';

        const lastFetch = s.last_fetched_at ? relativeTime(s.last_fetched_at) : 'never';
        const deleteBtn = s.is_custom
            ? `<button class="btn-delete" onclick="deleteSource('${escapeHtml(s.id)}')">Delete</button>`
            : '';

        return `
            <tr>
                <td><input type="checkbox" class="source-enabled-toggle" data-id="${escapeHtml(s.id)}" ${s.enabled ? 'checked' : ''}></td>
                <td>${escapeHtml(s.name)}</td>
                <td><span class="card-category ${categoryClass(s.category)}">${categoryLabel(s.category)}</span></td>
                <td>${statusDot} ${s.last_status_code || '--'}</td>
                <td>${s.article_count || 0}</td>
                <td class="mono">${escapeHtml(lastFetch)}</td>
                <td>${deleteBtn}</td>
            </tr>`;
    }).join('');

    // Attach toggle listeners
    tbody.querySelectorAll('.source-enabled-toggle').forEach(cb => {
        cb.addEventListener('change', async (e) => {
            const id = e.target.dataset.id;
            await apiFetch(`/sources/${id}`, {
                method: 'PUT',
                body: JSON.stringify({ enabled: e.target.checked ? 1 : 0 }),
            });
            showToast(`Source ${e.target.checked ? 'enabled' : 'disabled'}`, 'success');
        });
    });
}

// --- Actions ---

async function doRefresh() {
    const btn = document.getElementById('refresh-btn');
    btn.classList.add('spinning');
    try {
        const result = await apiFetch('/refresh', { method: 'POST' });
        showToast(`Refreshed: ${result.new_articles} new articles from ${result.sources_fetched} sources`, 'success');
        await fetchArticles();
        await fetchStats();
        await fetchSources();
    } catch (err) {
        showToast('Refresh failed', 'error');
    } finally {
        btn.classList.remove('spinning');
    }
}

async function deleteSource(id) {
    if (!confirm('Delete this custom source?')) return;
    try {
        await apiFetch(`/sources/${id}`, { method: 'DELETE' });
        showToast('Source deleted', 'success');
        await fetchSources();
    } catch {
        showToast('Failed to delete source', 'error');
    }
}

async function addSource() {
    const name = document.getElementById('new-source-name').value.trim();
    const url = document.getElementById('new-source-url').value.trim();
    const category = document.getElementById('new-source-category').value;

    if (!name || !url) {
        showToast('Name and URL are required', 'warning');
        return;
    }

    try {
        await apiFetch('/sources', {
            method: 'POST',
            body: JSON.stringify({ name, url, category }),
        });
        showToast(`Source "${name}" added!`, 'success');
        document.getElementById('new-source-name').value = '';
        document.getElementById('new-source-url').value = '';
        await fetchSources();
    } catch {
        showToast('Failed to add source', 'error');
    }
}

async function discoverSources() {
    const modal = document.getElementById('discover-modal');
    const loading = document.getElementById('discover-loading');
    const results = document.getElementById('discover-results');

    modal.classList.remove('hidden');
    loading.classList.remove('hidden');
    results.classList.add('hidden');

    try {
        const data = await apiFetch('/discover');
        loading.classList.add('hidden');
        results.classList.remove('hidden');

        if (data.discovered.length === 0) {
            results.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:20px;">No new sources discovered. All known sources are already added.</p>';
            return;
        }

        results.innerHTML = data.discovered.slice(0, 50).map(item => `
            <div class="discover-item">
                <span class="discover-item-url">${escapeHtml(item.name || item.url)}</span>
                <span class="discover-item-url" style="font-size:0.65rem;color:var(--text-muted)">${escapeHtml(item.url)}</span>
                <button class="btn-add-discover" onclick="addDiscoveredSource('${escapeHtml(item.url)}', '${escapeHtml(item.name || 'Discovered Feed')}')">+ Add</button>
            </div>
        `).join('');
    } catch {
        loading.classList.add('hidden');
        results.classList.remove('hidden');
        results.innerHTML = '<p style="color:var(--red);text-align:center">Failed to discover sources.</p>';
    }
}

async function addDiscoveredSource(url, name) {
    try {
        await apiFetch('/sources', {
            method: 'POST',
            body: JSON.stringify({ name, url, category: 'news' }),
        });
        showToast(`Added: ${name}`, 'success');
        await fetchSources();
    } catch {
        showToast('Failed to add source', 'error');
    }
}

// --- Event Listeners ---

document.addEventListener('DOMContentLoaded', () => {
    // Category nav
    document.querySelectorAll('.cat-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.cat-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentCategory = btn.dataset.category;
            currentPage = 1;
            fetchArticles();
        });
    });

    // Search
    const searchInput = document.getElementById('search-input');
    searchInput.addEventListener('input', () => {
        clearTimeout(searchDebounceTimer);
        searchDebounceTimer = setTimeout(() => {
            currentSearch = searchInput.value.trim();
            currentPage = 1;
            fetchArticles();
        }, 400);
    });

    // PoC filter
    document.getElementById('poc-filter').addEventListener('change', (e) => {
        pocOnly = e.target.checked;
        currentPage = 1;
        fetchArticles();
    });

    // Refresh button
    document.getElementById('refresh-btn').addEventListener('click', doRefresh);

    // Pagination
    document.getElementById('prev-page').addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            fetchArticles();
        }
    });
    document.getElementById('next-page').addEventListener('click', () => {
        currentPage++;
        fetchArticles();
    });

    // Source management modal
    document.getElementById('source-mgmt-btn').addEventListener('click', () => {
        document.getElementById('source-modal').classList.remove('hidden');
        fetchSources();
    });
    document.getElementById('modal-close').addEventListener('click', () => {
        document.getElementById('source-modal').classList.add('hidden');
    });
    document.getElementById('add-source-btn').addEventListener('click', addSource);

    // Discover modal
    document.getElementById('discover-btn').addEventListener('click', discoverSources);
    document.getElementById('discover-close').addEventListener('click', () => {
        document.getElementById('discover-modal').classList.add('hidden');
    });

    // OPML export
    document.getElementById('opml-export').addEventListener('click', () => {
        window.open(`${API_BASE}/opml`, '_blank');
    });

    // Mobile sidebar
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    document.getElementById('sidebar-toggle').addEventListener('click', () => {
        sidebar.classList.toggle('open');
        overlay.classList.toggle('active');
    });
    overlay.addEventListener('click', () => {
        sidebar.classList.remove('open');
        overlay.classList.remove('active');
    });

    // Close modals on outside click
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.classList.add('hidden');
        });
    });

    // Initial load
    fetchArticles();
    fetchStats();
    fetchSources();

    // Auto-refresh stats periodically
    setInterval(() => {
        fetchStats();
    }, 60000);
});
