// PSY9 Radar — frontend controller logic
// Keeps UI state, calls backend routes, and renders results for each tool.

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let allResults = {
    abuseipdb: [],
    virustotal: [],
    otx: [],
};
let currentSource = 'abuseipdb';
let currentSort = {
    abuseipdb: { col: null, asc: true },
    virustotal: { col: null, asc: true },
    otx: { col: null, asc: true },
};

// ---------------------------------------------------------------------------
// IP counter (live update as user types)
// ---------------------------------------------------------------------------
const ipInput  = document.getElementById('ipInput');
const ipCount  = document.getElementById('ipCount');
ipInput.addEventListener('input', () => {
    const lines = ipInput.value.split('\n').filter(l => l.trim() !== '');
    ipCount.textContent = `${lines.length} IP${lines.length !== 1 ? 's' : ''}`;
});

// ---------------------------------------------------------------------------
// Show / hide error
// ---------------------------------------------------------------------------
function showError(msg) {
    const el = document.getElementById('errorAlert');
    document.getElementById('errorMsg').textContent = msg;
    el.style.display = 'flex';
    setTimeout(() => { el.style.display = 'none'; }, 8000);
}
function hideError() { document.getElementById('errorAlert').style.display = 'none'; }

// ---------------------------------------------------------------------------
// Check IPs (main action)
// ---------------------------------------------------------------------------
async function checkIPs() {
    hideError();
    const raw = ipInput.value.trim();
    if (!raw) { showError('Please enter at least one IP address.'); return; }

    const lines = raw.split('\n').filter(l => l.trim() !== '');
    if (lines.length > 500) { showError('Maximum 500 IP addresses allowed per check.'); return; }

    // Show results card + loader
    const card = document.getElementById('resultsCard');
    card.style.display = 'block';
    document.getElementById('loader').classList.add('active');
    // Hide all tables / empty states for all sources before new query
    ['abuseipdb', 'virustotal', 'otx'].forEach(src => {
        const tw = document.getElementById(`tableWrapper-${src}`);
        const es = document.getElementById(`emptyState-${src}`);
        if (tw) tw.style.display = 'none';
        if (es) es.style.display = 'none';
    });
    document.getElementById('loaderCount').textContent     = `(${lines.length} IPs)`;

    // Disable button
    const btn = document.getElementById('checkBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Checking…';

    try {
        const source = currentSource || 'abuseipdb';
        const resp = await fetch('/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips: raw, source }),
        });
        const data = await resp.json();

        if (!resp.ok) {
            showError(data.error || 'Server error.');
            card.style.display = 'none';
            return;
        }

        allResults = data.results || { abuseipdb: [], virustotal: [], otx: [] };
        currentSort = {
            abuseipdb: { col: null, asc: true },
            virustotal: { col: null, asc: true },
            otx: { col: null, asc: true },
        };
        renderResults();
        updateDashboardCounters();
        updateRecentInvestigations();
        updateLastScanTime();
    } catch (err) {
        showError('Network error — could not reach the server.');
        card.style.display = 'none';
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-search"></i> Check IP Reputation';
        document.getElementById('loader').classList.remove('active');
    }
}

// ---------------------------------------------------------------------------
// Render results table
// ---------------------------------------------------------------------------
function renderResults(filteredList) {
    const source = currentSource;
    const data = filteredList || (allResults[source] || []);
    const tbody = document.getElementById(`resultsBody-${source}`);
    const wrapper = document.getElementById(`tableWrapper-${source}`);
    const empty   = document.getElementById(`emptyState-${source}`);

    if (data.length === 0) {
        if (wrapper) wrapper.style.display = 'none';
        if (empty) empty.style.display   = 'block';
        updateStats(data);
        return;
    }
    if (wrapper) wrapper.style.display = 'block';
    if (empty) empty.style.display   = 'none';
    updateStats(data);

    let html = '';
    data.forEach((r, i) => {
        const delay = Math.min(i * 30, 600);  // stagger animation
        if (source === 'abuseipdb' && r.error) {
            const ipStatus = r.ipStatus || 'N/A';
            html += `<tr style="animation-delay:${delay}ms">
                <td class="ip-cell">
                    <div class="ip-cell-wrap">
                        <button type="button"
                                class="ip-details-link ip-main"
                                data-ip="${esc(r.ip)}"
                                title="View detailed AbuseIPDB information">
                            ${esc(r.ip)}
                        </button>
                        <button type="button" class="ip-action-btn copy-btn"
                                aria-label="Copy IP"
                                onclick="copyIP('${esc(r.ip)}')">
                            <i class="bi bi-clipboard"></i>
                        </button>
                        <a class="ip-action-btn lookup-btn"
                           aria-label="Open AbuseIPDB in new tab"
                           href="https://www.abuseipdb.com/check/${encodeURIComponent(r.ip || '')}"
                           target="_blank" rel="noopener noreferrer">
                            <i class="bi bi-box-arrow-up-right"></i>
                        </a>
                    </div>
                </td>
                <td>${formatIpStatus(ipStatus)}</td>
                <td colspan="6" class="text-muted">
                    <i class="bi bi-exclamation-circle"></i> ${esc(r.error)}
                </td>
            </tr>`;
        } else if (source === 'abuseipdb') {
            const cls = confidenceClass(r.confidenceLevel);
            const ipStatus = r.ipStatus || 'New IP';
            html += `<tr style="animation-delay:${delay}ms">
                <td class="ip-cell">
                    <div class="ip-cell-wrap">
                        <button type="button"
                                class="ip-details-link ip-main"
                                data-ip="${esc(r.ip)}"
                                title="View detailed AbuseIPDB information">
                            ${esc(r.ip)}
                        </button>
                        <button type="button" class="ip-action-btn copy-btn"
                                aria-label="Copy IP"
                                onclick="copyIP('${esc(r.ip)}')">
                            <i class="bi bi-clipboard"></i>
                        </button>
                        <a class="ip-action-btn lookup-btn"
                           aria-label="Open AbuseIPDB in new tab"
                           href="https://www.abuseipdb.com/check/${encodeURIComponent(r.ip || '')}"
                           target="_blank" rel="noopener noreferrer">
                            <i class="bi bi-box-arrow-up-right"></i>
                        </a>
                    </div>
                </td>
                <td>${formatIpStatus(ipStatus)}</td>
                <td>
                    <div class="score-bar-wrap">
                        <span class="font-mono">${r.abuseConfidenceScore}</span>
                        <div class="score-bar">
                            <div class="score-bar-fill ${cls}" style="width:${r.abuseConfidenceScore}%"></div>
                        </div>
                    </div>
                </td>
                <td>${formatCountry(r)}</td>
                <td>${esc(r.isp || 'N/A')}</td>
                <td class="font-mono">${esc(r.domain || 'N/A')}</td>
                <td class="font-mono">${r.totalReports ?? 0}</td>
                <td>${formatConfidence(r.confidenceLevel)}</td>
            </tr>`;
        } else if (r.error) {
            const colspan = source === 'virustotal' ? 5 : 3;
            html += `<tr style="animation-delay:${delay}ms">
                <td class="ip-cell">${esc(r.ip)}</td>
                <td colspan="${colspan}" class="text-muted">
                    <i class="bi bi-exclamation-circle"></i> ${esc(r.error)}
                </td>
            </tr>`;
        } else if (source === 'virustotal') {
            html += `<tr style="animation-delay:${delay}ms">
                <td class="ip-cell">${esc(r.ip)}</td>
                <td class="font-mono">${r.malicious ?? 0}</td>
                <td class="font-mono">${r.suspicious ?? 0}</td>
                <td class="font-mono">${r.harmless ?? 0}</td>
                <td>${esc(r.country || 'N/A')}</td>
                <td class="font-mono">${esc(r.network || 'N/A')}</td>
            </tr>`;
        } else if (source === 'otx') {
            html += `<tr style="animation-delay:${delay}ms">
                <td class="ip-cell">${esc(r.ip)}</td>
                <td>${esc(r.country || 'N/A')}</td>
                <td class="font-mono">${esc(r.asn || 'N/A')}</td>
                <td class="font-mono">${r.pulseCount ?? 0}</td>
            </tr>`;
        }
    });
    tbody.innerHTML = html;
    if (source === 'abuseipdb') {
        attachIpDetailsHandlers();
    }
}

// ---------------------------------------------------------------------------
// Stats bar
// ---------------------------------------------------------------------------
function updateStats(data) {
    // Stats are only meaningful for AbuseIPDB confidence levels
    if (currentSource !== 'abuseipdb') {
        document.getElementById('statsBar').innerHTML = '';
        return;
    }
    const total  = data.length;
    const low    = data.filter(r => r.confidenceLevel === 'Low').length;
    const med    = data.filter(r => r.confidenceLevel === 'Medium').length;
    const high   = data.filter(r => r.confidenceLevel === 'High').length;
    const crit   = data.filter(r => r.confidenceLevel === 'Critical').length;
    const errs   = data.filter(r => r.error).length;

    document.getElementById('statsBar').innerHTML = `
        <span class="stat-chip total"><i class="bi bi-globe2"></i> ${total} total</span>
        <span class="stat-chip clean"><i class="bi bi-check-circle-fill"></i> ${low} low</span>
        <span class="stat-chip suspect"><i class="bi bi-exclamation-triangle-fill"></i> ${med} medium</span>
        <span class="stat-chip high-chip"><i class="bi bi-exclamation-diamond-fill"></i> ${high} high</span>
        <span class="stat-chip mal"><i class="bi bi-x-octagon-fill"></i> ${crit} critical</span>
        ${errs ? `<span class="stat-chip err"><i class="bi bi-bug-fill"></i> ${errs} errors</span>` : ''}
    `;
}

// ---------------------------------------------------------------------------
// Sort
// ---------------------------------------------------------------------------
function sortTable(col) {
    const source = currentSource;
    const sortState = currentSort[source];
    if (sortState.col === col) sortState.asc = !sortState.asc;
    else { sortState.col = col; sortState.asc = true; }

    // Update header classes
    document.querySelectorAll(`#panel-${source} .results-table thead th`).forEach(th => {
        th.classList.remove('sorted-asc', 'sorted-desc');
        if (th.dataset.col === col) th.classList.add(sortState.asc ? 'sorted-asc' : 'sorted-desc');
    });

    const gettersBySource = {
        abuseipdb: {
            ip:      r => r.ip || '',
            status:  r => (r.ipStatus || '').toLowerCase(),
            score:   r => r.error ? -1 : (r.abuseConfidenceScore ?? 0),
            country: r => r.countryName || '',
            isp:     r => r.isp || '',
            domain:  r => r.domain || '',
            reports: r => r.error ? -1 : (r.totalReports ?? 0),
            confidence: r => r.error ? '' : (r.confidenceLevel || ''),
        },
        virustotal: {
            ip:        r => r.ip || '',
            malicious: r => r.error ? -1 : (r.malicious ?? 0),
            suspicious:r => r.error ? -1 : (r.suspicious ?? 0),
            harmless:  r => r.error ? -1 : (r.harmless ?? 0),
            country:   r => r.country || '',
            network:   r => r.network || '',
        },
        otx: {
            ip:     r => r.ip || '',
            country:r => r.country || '',
            asn:    r => r.asn || '',
            pulse:  r => r.error ? -1 : (r.pulseCount ?? 0),
        },
    };

    const getter = gettersBySource[source] || {};
    const fn = getter[col] || (r => '');
    const list = allResults[source] || [];
    list.sort((a, b) => {
        let va = fn(a), vb = fn(b);
        if (typeof va === 'string') { va = va.toLowerCase(); vb = vb.toLowerCase(); }
        if (va < vb) return sortState.asc ? -1 : 1;
        if (va > vb) return sortState.asc ? 1  : -1;
        return 0;
    });
    renderResults();
}

// ---------------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------------
function filterTable() {
    const q = document.getElementById('filterInput').value.toLowerCase();
    const source = currentSource;
    const base = allResults[source] || [];
    if (!q) { renderResults(); return; }
    const filtered = base.filter(r => {
        if (source === 'abuseipdb') {
            return (r.ip || '').toLowerCase().includes(q) ||
                   (r.ipStatus || '').toLowerCase().includes(q) ||
                   (r.countryName || '').toLowerCase().includes(q) ||
                   (r.countryAlpha3 || '').toLowerCase().includes(q) ||
                   (r.countryCode || '').toLowerCase().includes(q) ||
                   (r.isp || '').toLowerCase().includes(q) ||
                   (r.domain || '').toLowerCase().includes(q) ||
                   (r.confidenceLevel || '').toLowerCase().includes(q) ||
                   (String(r.totalReports ?? '')).toLowerCase().includes(q) ||
                   (r.error || '').toLowerCase().includes(q);
        }
        if (source === 'virustotal') {
            return (r.ip || '').toLowerCase().includes(q) ||
                   (r.country || '').toLowerCase().includes(q) ||
                   (r.network || '').toLowerCase().includes(q) ||
                   (String(r.malicious ?? '')).toLowerCase().includes(q) ||
                   (String(r.suspicious ?? '')).toLowerCase().includes(q) ||
                   (String(r.harmless ?? '')).toLowerCase().includes(q) ||
                   (r.error || '').toLowerCase().includes(q);
        }
        // OTX
        return (r.ip || '').toLowerCase().includes(q) ||
               (r.country || '').toLowerCase().includes(q) ||
               (r.asn || '').toLowerCase().includes(q) ||
               (String(r.pulseCount ?? '')).toLowerCase().includes(q) ||
               (r.error || '').toLowerCase().includes(q);
    });
    renderResults(filtered);
}

// ---------------------------------------------------------------------------
// Export CSV
// ---------------------------------------------------------------------------
async function exportCSV() {
    const source = currentSource;
    const current = allResults[source] || [];
    if (!current.length) { showError('No results to export.'); return; }

    try {
        const resp = await fetch('/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ results: current, source }),
        });

        if (!resp.ok) { showError('Export failed.'); return; }

        const blob = await resp.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = 'ip_reputation_report.csv';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    } catch {
        showError('Export error — could not generate CSV.');
    }
}

// ---------------------------------------------------------------------------
// Clear
// ---------------------------------------------------------------------------
function clearAll() {
    ipInput.value = '';
    ipCount.textContent = '0 IPs';
    allResults = { abuseipdb: [], virustotal: [], otx: [] };
    document.getElementById('resultsCard').style.display = 'none';
    hideError();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function esc(s)  { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function confidenceClass(level) {
    return { Low: 'clean', Medium: 'suspicious', High: 'high', Critical: 'malicious' }[level] || 'error';
}
function formatIpStatus(status) {
    const label = (status || 'New IP').toString();
    const lower = label.toLowerCase();
    if (lower === 'repeated ip') {
        return `<span class="threat-badge-url suspicious"><i class="bi bi-arrow-repeat"></i> Repeated IP</span>`;
    }
    if (lower === 'new ip') {
        return `<span class="threat-badge-url safe"><i class="bi bi-check-circle"></i> New IP</span>`;
    }
    return `<span class="threat-badge-url">${esc(label)}</span>`;
}
function formatCountry(r) {
    const name = r.countryName || 'Unknown';
    const a3   = r.countryAlpha3 || 'N/A';
    if (name === 'Unknown') return '<span class="text-muted">Unknown</span>';
    return `
        <div class="country-name">${esc(name)}</div>
        <div class="country-code">${esc(a3)}</div>
    `;
}
function formatConfidence(level) {
    const map = {
        Low:      'clean',
        Medium:   'suspicious',
        High:     'high',
        Critical: 'malicious',
    };
    const cls = map[level] || 'error';
    return `<span class="threat-badge ${cls}">${esc(level || 'N/A')}</span>`;
}
function copyIP(ip) {
    const v = (ip || '').toString().trim();
    if (!v) return;
    navigator.clipboard?.writeText(v);
}
function formatDate(d) {
    if (!d || d === 'Never') return '<span class="text-muted">Never</span>';
    try { return new Date(d).toLocaleDateString('en-US', { year:'numeric', month:'short', day:'numeric' }); }
    catch { return esc(d); }
}

// ---------------------------------------------------------------------------
// Dashboard counter + info card updates
// ---------------------------------------------------------------------------
function updateDashboardCounters() {
    const data = allResults.abuseipdb || [];
    const total = data.length;
    const malicious = data.filter(r => !r.error && (r.confidenceLevel === 'Critical' || r.confidenceLevel === 'High')).length;
    const suspicious = data.filter(r => !r.error && r.confidenceLevel === 'Medium').length;
    const clean = data.filter(r => !r.error && r.confidenceLevel === 'Low').length;

    animateCounter('cntTotal', total);
    animateCounter('cntMalicious', malicious);
    animateCounter('cntSuspicious', suspicious);
    animateCounter('cntClean', clean);
}

function animateCounter(id, target) {
    const el = document.getElementById(id);
    const start = parseInt(el.textContent) || 0;
    if (start === target) return;
    const duration = 600;
    const startTime = performance.now();
    function tick(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(start + (target - start) * eased);
        if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
}

function updateRecentInvestigations() {
    const data = allResults.abuseipdb || [];
    const container = document.getElementById('recentInvestigations');
    if (!data.length) {
        container.innerHTML = '<div class="info-card-empty"><i class="bi bi-inbox"></i> No investigations yet</div>';
        return;
    }
    const recent = data.slice(0, 5);
    container.innerHTML = recent.map(r => {
        const badge = r.error
            ? '<span class="threat-badge error">Error</span>'
            : formatConfidence(r.confidenceLevel);
        return `<div class="recent-item">
            <span class="font-mono">${esc(r.ip)}</span>
            ${badge}
        </div>`;
    }).join('');
}

function updateLastScanTime() {
    const el = document.getElementById('lastScanTime');
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ---------------------------------------------------------------------------
// IP detail modal
// ---------------------------------------------------------------------------
function attachIpDetailsHandlers() {
    const links = document.querySelectorAll('#resultsBody-abuseipdb .ip-details-link');
    links.forEach(link => {
        link.addEventListener('click', async (ev) => {
            ev.preventDefault();
            const ip = link.dataset.ip;
            const modalEl = document.getElementById('ipDetailsModal');
            const modalBody = document.getElementById('ipDetailsContent');
            const subtitle = document.getElementById('ipDetailsSubtitle');

            subtitle.textContent = ip || '';
            modalBody.innerHTML = `
                <div class="text-center text-muted py-4">
                    <div class="spinner-border text-info mb-3" role="status"></div>
                    <div>Querying AbuseIPDB for ${esc(ip)}…</div>
                </div>`;

            const modal = new bootstrap.Modal(modalEl);
            modal.show();

            try {
                const resp = await fetch('/ip-details/' + encodeURIComponent(ip));
                const data = await resp.json();

                if (!resp.ok || data.error) {
                    modalBody.innerHTML = `
                        <div class="alert-custom">
                            <i class="bi bi-exclamation-triangle-fill"></i>
                            <span>${esc(data.error || 'Unable to load IP details.')}</span>
                        </div>`;
                    return;
                }

                modalBody.innerHTML = buildDetailsHTML(data);
            } catch (e) {
                modalBody.innerHTML = `
                    <div class="alert-custom">
                        <i class="bi bi-exclamation-triangle-fill"></i>
                        <span>Network error while loading IP details.</span>
                    </div>`;
            }
        }, { once: false });
    });
}

function buildDetailsHTML(d) {
    const score = d.abuseConfidenceScore ?? 0;
    const scoreLabel = d.confidenceLevel || 'Unknown';
    const countryName = d.countryName || 'Unknown';
    const alpha3 = d.countryAlpha3 || 'N/A';
    const hostnames = (d.hostnames || []).filter(Boolean);
    const comments = (d.comments || []).filter(Boolean);

    const hostnameHtml = hostnames.length
        ? hostnames.map(h => `<span class="badge bg-secondary-subtle text-light font-mono me-1 mb-1">${esc(h)}</span>`).join(' ')
        : '<span class="text-muted">N/A</span>';

    const commentsHtml = comments.length
        ? comments.map(c => `<li class="mb-2"><i class="bi bi-chat-right-text me-1 text-muted"></i>${esc(c)}</li>`).join('')
        : '<span class="text-muted">No public comments available.</span>';

    let scoreBarClass = 'ip-score-bar-red';
    if (score <= 20) scoreBarClass = 'ip-score-bar-green';
    else if (score <= 50) scoreBarClass = 'ip-score-bar-yellow';
    else if (score <= 80) scoreBarClass = 'ip-score-bar-orange';

    const reportsText = typeof d.totalReports === 'number' ? d.totalReports : 0;

    return `
        <div class="ip-details-card">
            <div class="ip-banner mb-3">
                <div class="ip-banner-ip font-mono">${esc(d.ip || '')}</div>
                <div class="ip-banner-sub">was found in our database!</div>
                <div class="ip-banner-meta">
                    This IP was reported <span class="fw-bold">${reportsText}</span> time${reportsText === 1 ? '' : 's'}.
                    Confidence of abuse is <span class="fw-bold">${score}%</span>.
                </div>
            </div>

            <div class="ip-score-card mb-3">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <div class="ip-details-label mb-0">Abuse Confidence Score</div>
                    <div class="small text-muted">Score: <span class="font-mono fw-bold">${score}/100</span></div>
                </div>
                <div class="progress ip-score-progress-lg">
                    <div class="progress-bar ${scoreBarClass}"
                         role="progressbar"
                         style="width:${score}%;"
                         aria-valuenow="${score}" aria-valuemin="0" aria-valuemax="100">
                        ${score}%
                    </div>
                </div>
                <div class="mt-2">${formatConfidence(scoreLabel)}</div>
            </div>

            <div class="ip-primary-info card bg-transparent border-0 mb-3">
                <div class="card-body py-3">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <div class="ip-info-block">
                                <div class="ip-info-label text-muted">Country</div>
                                <div class="ip-info-value fw-semibold">
                                    ${esc(countryName)} <span class="text-muted">(${esc(alpha3)})</span>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="ip-info-block">
                                <div class="ip-info-label text-muted">ISP</div>
                                <div class="ip-info-value fw-semibold">${esc(d.isp || 'N/A')}</div>
                            </div>
                        </div>
                    </div>
                    <div class="row g-3 mt-2">
                        <div class="col-md-6">
                            <div class="ip-info-block">
                                <div class="ip-info-label text-muted">Domain Name</div>
                                <div class="ip-info-value fw-semibold font-mono">${esc(d.domain || 'N/A')}</div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="ip-info-block">
                                <div class="ip-info-label text-muted">Usage Type</div>
                                <div class="ip-info-value fw-semibold">${esc(d.usageType || 'N/A')}</div>
                            </div>
                        </div>
                    </div>
                    <div class="row g-3 mt-2">
                        <div class="col-md-6">
                            <div class="ip-info-block">
                                <div class="ip-info-label text-muted">Total Reports</div>
                                <div class="ip-info-value fw-semibold font-mono">${reportsText}</div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="ip-info-block">
                                <div class="ip-info-label text-muted">Last Reported At</div>
                                <div class="ip-info-value fw-semibold">${formatDate(d.lastReportedAt)}</div>
                            </div>
                        </div>
                    </div>
                    <div class="row g-3 mt-2">
                        <div class="col-md-6">
                            <div class="ip-info-block">
                                <div class="ip-info-label text-muted">Whitelisted</div>
                                <div class="ip-info-value fw-semibold">
                                    ${d.isWhitelisted ? '<span class="badge bg-success-subtle text-success">Yes</span>' : '<span class="badge bg-secondary-subtle text-muted">No</span>'}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="ip-details-section mb-3">
                <div class="ip-details-label mb-1">Hostnames</div>
                <div>${hostnameHtml}</div>
            </div>

            <div class="ip-details-section">
                <div class="ip-details-label mb-1">Recent Public Comments</div>
                <div>
                    ${comments.length ? `<ul class="list-unstyled small mb-0">${commentsHtml}</ul>` : commentsHtml}
                </div>
            </div>
        </div>
    `;
}

// ---------------------------------------------------------------------------
// Source switching helper
// ---------------------------------------------------------------------------
function switchSource(source) {
    currentSource = source;
    // When switching tabs, re-render that source and clear stats/filter view
    document.getElementById('filterInput').value = '';
    renderResults();
}

// ---------------------------------------------------------------------------
// Sidebar section switching
// ---------------------------------------------------------------------------
function showToolSection(sectionId, clickedItem) {
    // Hide all tool sections
    document.querySelectorAll('.tool-section').forEach(sec => sec.style.display = 'none');
    // Show target section
    const target = document.getElementById(sectionId);
    if (target) target.style.display = 'block';
    // Update sidebar active state
    document.querySelectorAll('.sidebar-item').forEach(item => item.classList.remove('active'));
    if (clickedItem) clickedItem.classList.add('active');
}

// ---------------------------------------------------------------------------
// IP Comparison Tool
// ---------------------------------------------------------------------------
function compareIPs() {
    const rawA = document.getElementById('compareListA').value.trim();
    const rawB = document.getElementById('compareListB').value.trim();

    if (!rawA || !rawB) {
        showError('Please enter IP addresses in both List A and List B.');
        return;
    }

    // Parse, clean, and deduplicate
    const parse = raw => {
        return [...new Set(
            raw.split('\n')
               .map(line => line.trim())
               .filter(line => line.length > 0)
        )];
    };

    const listA = parse(rawA);
    const listB = parse(rawB);
    const setB  = new Set(listB);
    const common = listA.filter(ip => setB.has(ip));

    // Update stats
    document.getElementById('compareStatsBar').style.display = 'grid';
    document.getElementById('statListA').textContent   = listA.length;
    document.getElementById('statListB').textContent   = listB.length;
    document.getElementById('statMatches').textContent  = common.length;

    // Show results card
    const card = document.getElementById('compareResultsCard');
    card.style.display = 'block';
    const body = document.getElementById('compareResultsBody');

    if (common.length === 0) {
        body.innerHTML = `
            <div class="compare-no-match">
                <i class="bi bi-shield-x"></i>
                <p>No matching IP addresses found.</p>
            </div>`;
        return;
    }

    let rows = common.map((ip, i) => {
        const delay = Math.min(i * 30, 600);
        return `<tr style="animation-delay:${delay}ms"><td class="font-mono">${esc(ip)}</td></tr>`;
    }).join('');

    body.innerHTML = `
        <div class="compare-result-header">
            <i class="bi bi-check-circle-fill"></i>
            Common IPs Found: <span class="font-mono fw-bold">${common.length}</span>
        </div>
        <div class="table-wrapper">
            <table class="results-table compare-results-table">
                <thead>
                    <tr><th>Common IP Addresses</th></tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>`;
}

function clearCompare() {
    document.getElementById('compareListA').value = '';
    document.getElementById('compareListB').value = '';
    document.getElementById('compareStatsBar').style.display = 'none';
    document.getElementById('compareResultsCard').style.display = 'none';
    hideError();
}

// ---------------------------------------------------------------------------
// IP List Single-Line Converter
// ---------------------------------------------------------------------------
function convertIPs() {
    const inputEl = document.getElementById('converterInput');
    const outputEl = document.getElementById('converterOutput');
    if (!inputEl || !outputEl) return;

    const raw = (inputEl.value || '').trim();
    if (!raw) {
        outputEl.value = '';
        showError('Please paste at least one IP address to convert.');
        return;
    }

    const ips = raw
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);

    const singleLine = ips.join(',');
    outputEl.value = singleLine;
}

async function copySingleLine() {
    const outputEl = document.getElementById('converterOutput');
    if (!outputEl || !outputEl.value) {
        showError('Nothing to copy — please run a conversion first.');
        return;
    }

    const text = outputEl.value;

    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
        } else {
            const temp = document.createElement('textarea');
            temp.value = text;
            document.body.appendChild(temp);
            temp.select();
            document.execCommand('copy');
            temp.remove();
        }
    } catch (e) {
        showError('Unable to copy to clipboard. Please copy manually.');
    }
}

// ---------------------------------------------------------------------------
// Domain Intelligence Tool
// ---------------------------------------------------------------------------
async function lookupDomain() {
    const input = document.getElementById('domainInput');
    const card = document.getElementById('domainResultsCard');
    const body = document.getElementById('domainResultsBody');
    if (!input || !card || !body) return;

    const domain = (input.value || '').trim();
    if (!domain) {
        showError('Please enter a domain name to lookup.');
        return;
    }

    card.style.display = 'block';
    body.innerHTML = `
        <div class="text-center text-muted py-4">
            <div class="spinner-border text-info mb-3" role="status"></div>
            <div>Looking up domain intelligence for <span class="font-mono">${esc(domain)}</span>…</div>
        </div>`;

    try {
        const resp = await fetch('/domain-intel', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain }),
        });
        const data = await resp.json();

        if (!resp.ok || data.error) {
            body.innerHTML = `
                <div class="alert-custom">
                    <i class="bi bi-exclamation-triangle-fill"></i>
                    <span>${esc(data.error || 'Unable to retrieve domain information.')}</span>
                </div>`;
            return;
        }

        const dns = data.dns_records || {};
        const recordSummary = data.record_summary || 'None';

        const dnsRows = Object.keys(dns).length
            ? Object.entries(dns).map(([rtype, values]) => {
                  const valList = (values || []).map(v => `<li>${esc(v)}</li>`).join('');
                  return `<tr>
                            <th>${esc(rtype)} Records</th>
                            <td><ul class="domain-dns-list">${valList}</ul></td>
                          </tr>`;
              }).join('')
            : '<tr><th>DNS Records</th><td class="text-muted">No DNS records found.</td></tr>';

        body.innerHTML = `
            <table class="domain-table">
                <tr>
                    <th>Domain</th>
                    <td class="font-mono fw-semibold">${esc(data.domain || domain)}</td>
                </tr>
                <tr>
                    <th>Registrar</th>
                    <td>${esc(data.registrar || 'N/A')}</td>
                </tr>
                <tr>
                    <th>Created</th>
                    <td>${esc(data.created || 'N/A')}</td>
                </tr>
                <tr>
                    <th>Hosting IP</th>
                    <td class="font-mono">${esc(data.hosting_ip || 'N/A')}</td>
                </tr>
                <tr>
                    <th>Record Types</th>
                    <td>${esc(recordSummary)}</td>
                </tr>
                ${dnsRows}
            </table>
        `;
    } catch (e) {
        body.innerHTML = `
            <div class="alert-custom">
                <i class="bi bi-exclamation-triangle-fill"></i>
                <span>Unable to retrieve domain information.</span>
            </div>`;
    }
}

// ---------------------------------------------------------------------------
// URL Intelligence Tool
// ---------------------------------------------------------------------------
async function lookupUrl() {
    const input = document.getElementById('urlInput');
    const card = document.getElementById('urlResultsCard');
    const body = document.getElementById('urlResultsBody');
    if (!input || !card || !body) return;

    const url = (input.value || '').trim();
    if (!url) {
        showError('Please enter a URL to check.');
        return;
    }

    card.style.display = 'block';
    body.innerHTML = `
        <div class="text-center text-muted py-4">
            <div class="spinner-border text-info mb-3" role="status"></div>
            <div>Checking URL intelligence for <span class="font-mono">${esc(url)}</span>…</div>
        </div>`;

    try {
        const resp = await fetch('/url-intel', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
        });
        const data = await resp.json();

        if (!resp.ok || data.error) {
            body.innerHTML = `
                <div class="alert-custom">
                    <i class="bi bi-exclamation-triangle-fill"></i>
                    <span>${esc(data.error || 'Unable to retrieve URL information.')}</span>
                </div>`;
            return;
        }

        const vt = data.virustotal || {};
        const mal = vt.malicious ?? 0;
        const sus = vt.suspicious ?? 0;
        const harmless = vt.harmless ?? 0;
        const total = vt.total_engines ?? (mal + sus + harmless);

        const threat = data.threat_level || 'Unknown';
        let badgeClass = 'safe';
        if (threat === 'Critical' || threat === 'High') badgeClass = 'malicious';
        else if (threat === 'Medium') badgeClass = 'suspicious';

        const vtError = vt.error;

        body.innerHTML = vtError
            ? `
                <div class="alert-custom">
                    <i class="bi bi-exclamation-triangle-fill"></i>
                    <span>${esc(vtError)}</span>
                </div>`
            : `
            <table class="domain-table">
                <tr>
                    <th>URL</th>
                    <td class="font-mono fw-semibold">${esc(data.url || url)}</td>
                </tr>
                <tr>
                    <th>Reputation Score</th>
                    <td>${vt.reputation ?? 0}</td>
                </tr>
                <tr>
                    <th>Malicious Detections</th>
                    <td>${mal} (Suspicious: ${sus}, Harmless: ${harmless})</td>
                </tr>
                <tr>
                    <th>Scan Engines</th>
                    <td>${total}</td>
                </tr>
                <tr>
                    <th>Threat Level</th>
                    <td>
                        <span class="threat-badge-url ${badgeClass}">
                            <i class="bi bi-shield-exclamation"></i> ${esc(threat)}
                        </span>
                    </td>
                </tr>
                <tr>
                    <th>OTX Pulses</th>
                    <td>${data.otx_pulse_count != null ? data.otx_pulse_count : 'N/A'}</td>
                </tr>
            </table>
        `;
    } catch (e) {
        body.innerHTML = `
            <div class="alert-custom">
                <i class="bi bi-exclamation-triangle-fill"></i>
                <span>Unable to retrieve URL information.</span>
            </div>`;
    }
}

// ---------------------------------------------------------------------------
// File Hash Intelligence Tool
// ---------------------------------------------------------------------------
async function lookupHash() {
    const input = document.getElementById('hashInput');
    const card = document.getElementById('hashResultsCard');
    const body = document.getElementById('hashResultsBody');
    if (!input || !card || !body) return;

    const hash = (input.value || '').trim();
    if (!hash) {
        showError('Please enter a file hash to check.');
        return;
    }

    card.style.display = 'block';
    body.innerHTML = `
        <div class="text-center text-muted py-4">
            <div class="spinner-border text-info mb-3" role="status"></div>
            <div>Querying VirusTotal for hash <span class="font-mono">${esc(hash)}</span>…</div>
        </div>`;

    try {
        const resp = await fetch('/hash-intel', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hash }),
        });
        const data = await resp.json();

        if (!resp.ok || data.error) {
            body.innerHTML = `
                <div class="alert-custom">
                    <i class="bi bi-exclamation-triangle-fill"></i>
                    <span>${esc(data.error || 'Unable to retrieve file hash information.')}</span>
                </div>`;
            return;
        }

        const threat = data.threat_level || 'Unknown';
        let badgeClass = 'safe';
        if (threat === 'Critical' || threat === 'High') badgeClass = 'malicious';
        else if (threat === 'Medium') badgeClass = 'suspicious';

        body.innerHTML = `
            <table class="domain-table">
                <tr>
                    <th>Hash</th>
                    <td class="font-mono fw-semibold">${esc(data.hash || hash)}</td>
                </tr>
                <tr>
                    <th>Detection Ratio</th>
                    <td>${esc(data.detection_ratio || '')}</td>
                </tr>
                <tr>
                    <th>Malicious</th>
                    <td>${data.malicious ?? 0} (Suspicious: ${data.suspicious ?? 0})</td>
                </tr>
                <tr>
                    <th>Malware Type</th>
                    <td>${esc(data.malware_type || 'Unknown')}</td>
                </tr>
                <tr>
                    <th>Threat Level</th>
                    <td>
                        <span class="threat-badge-url ${badgeClass}">
                            <i class="bi bi-bug-fill"></i> ${esc(threat)}
                        </span>
                    </td>
                </tr>
            </table>
        `;
    } catch (e) {
        body.innerHTML = `
            <div class="alert-custom">
                <i class="bi bi-exclamation-triangle-fill"></i>
                <span>Unable to retrieve file hash information.</span>
            </div>`;
    }
}

