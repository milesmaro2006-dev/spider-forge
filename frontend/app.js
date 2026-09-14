// frontend/app.js
// SpiderForge — Frontend controller
// Compatible with both `{status, findings}` and legacy `{status, data:{findings}}` responses.

/* ───────────────────────── Entry point ───────────────────────── */
async function startUnifiedScan() {
    const input       = document.getElementById('target-url');
    const targetUrl   = (input.value || '').trim();
    const scanBtn     = document.getElementById('scan-btn');
    const loadingDiv  = document.getElementById('loading');
    const resultsDiv  = document.getElementById('scan-results');
    const vulnDiv     = document.getElementById('vulnerabilities');
    const countBadge  = document.getElementById('findings-count');

    if (!targetUrl) {
        input.focus();
        showError(resultsDiv, vulnDiv, countBadge,
            'Please specify a target URL.', targetUrl);
        return;
    }

    // ── Loading state ──
    scanBtn.disabled = true;
    scanBtn.classList.add('loading');
    loadingDiv.style.display = 'flex';
    resultsDiv.style.display = 'none';
    vulnDiv.replaceChildren();

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: targetUrl })
        });

        let data = {};
        try { data = await response.json(); } catch (_) { data = {}; }

        const payload =
            (data && typeof data === 'object' && data.data && typeof data.data === 'object')
                ? data.data
                : (data || {});

        const findings = Array.isArray(payload.findings) ? payload.findings : [];
        const resolvedTarget = payload.target || data.target || targetUrl;
        const totalIssues =
            typeof payload.total_issues === 'number' ? payload.total_issues :
            typeof data.total_issues     === 'number' ? data.total_issues :
            findings.length;

        const isExplicitError = data.status === 'error' || response.status >= 400;

        loadingDiv.style.display = 'none';
        scanBtn.classList.remove('loading');
        scanBtn.disabled = false;

        if (isExplicitError) {
            const detail =
                data.detail || payload.detail || data.message ||
                `Request failed (HTTP ${response.status})`;
            showError(resultsDiv, vulnDiv, countBadge, detail, resolvedTarget);
            return;
        }

        resultsDiv.style.display = 'block';
        countBadge.textContent = `${totalIssues} ${totalIssues === 1 ? 'Issue' : 'Issues'}`;
        countBadge.dataset.state = findings.length > 0 ? 'alert' : 'clean';

        if (findings.length === 0) {
            vulnDiv.appendChild(buildEmptyState());
        } else {
            const order = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
            findings
                .slice()
                .sort((a, b) => (order[a.severity] ?? 99) - (order[b.severity] ?? 99))
                .forEach((v, i) => vulnDiv.appendChild(buildFindingCard(v, i)));
        }

        // ── Report actions bar ──
        vulnDiv.appendChild(buildReportBar(targetUrl));

    } catch (err) {
        console.error('Scan Error:', err);
        loadingDiv.style.display = 'none';
        scanBtn.classList.remove('loading');
        scanBtn.disabled = false;
        showError(resultsDiv, vulnDiv, countBadge,
            'Could not reach the SpiderForge engine. Is the backend running?',
            targetUrl);
    }
}

/* ───────────────────────── Report bar ───────────────────────── */

function buildReportBar(targetUrl) {
    // Workspace name = جزء من الـ target بدون http وبدون رموز غريبة
    const slug = (targetUrl || '')
        .replace(/^https?:\/\//, '')
        .replace(/[^a-zA-Z0-9._-]/g, '_')
        .slice(0, 60) || 'scan';

    const bar = document.createElement('div');
    bar.className = 'report-bar';
    bar.innerHTML = `
        <div class="report-bar-title">Reports</div>
        <div class="report-bar-actions">
            <button type="button" data-action="view-pdf"   data-ws="${slug}">View PDF</button>
            <a      data-action="dl-pdf"   data-ws="${slug}"
                    href="/reports/${slug}/download/report.pdf?as_attachment=true"
                    download>
                <button type="button">Download PDF</button>
            </a>
            <button type="button" data-action="view-html"  data-ws="${slug}">View HTML</button>
        </div>
        <div class="report-bar-hint">
            التقارير متاحة فقط بعد تشغيل "Generate Reports" من الـ CLI لهذا الفحص.
        </div>
    `;

    bar.addEventListener('click', (ev) => {
        const btn = ev.target.closest('button[data-action], a[data-action]');
        if (!btn) return;
        const action = btn.dataset.action;
        const ws = btn.dataset.ws;
        if (!ws) return;

        if (action === 'view-pdf') {
            window.open(`/reports/${ws}/view/report.pdf`, '_blank');
        } else if (action === 'view-html') {
            window.open(`/reports/${ws}/view/report.html`, '_blank');
        }
        // dl-pdf: default anchor behavior (download attribute) — لا نحتاج تدخل
    });

    return bar;
}

/* ───────────────────────── Builders ───────────────────────── */

function buildFindingCard(vuln, index) {
    const severity = normalizeSeverity(vuln.severity);

    const card = document.createElement('article');
    card.className = `finding severity-${severity}`;
    card.style.animationDelay = `${Math.min(index * 40, 320)}ms`;

    const header = document.createElement('div');
    header.className = 'finding-header';

    const titleWrap = document.createElement('div');

    const title = document.createElement('h4');
    title.textContent = vuln.title || vuln.type || 'Finding';
    titleWrap.appendChild(title);

    const paramText = (vuln.param && String(vuln.param).trim()) || 'N/A';
    if (paramText !== 'N/A') {
        const paramEl = document.createElement('span');
        paramEl.className = 'finding-param';
        paramEl.textContent = paramText;
        titleWrap.appendChild(paramEl);
    }

    const badge = document.createElement('span');
    badge.className = `sev-badge sev-${severity.toLowerCase()}`;
    badge.textContent = severity.toUpperCase();

    header.appendChild(titleWrap);
    header.appendChild(badge);
    card.appendChild(header);

    if (vuln.description) {
        const desc = document.createElement('p');
        desc.className = 'finding-desc';
        desc.textContent = vuln.description;
        card.appendChild(desc);
    }

    if (vuln.payload && String(vuln.payload).trim()) {
        card.appendChild(buildCodeBlock('Payload', String(vuln.payload)));
    }

    if (vuln.evidence && String(vuln.evidence).trim()) {
        card.appendChild(buildCodeBlock('Evidence', String(vuln.evidence)));
    }

    return card;
}

function buildCodeBlock(label, value) {
    const wrap = document.createElement('div');
    wrap.className = 'code-block';

    const head = document.createElement('div');
    head.className = 'code-head';

    const labelEl = document.createElement('span');
    labelEl.textContent = label;

    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'copy-btn';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', () => copyToClipboard(value, copyBtn));

    head.appendChild(labelEl);
    head.appendChild(copyBtn);

    const pre = document.createElement('pre');
    const code = document.createElement('code');
    code.textContent = value;
    pre.appendChild(code);

    wrap.appendChild(head);
    wrap.appendChild(pre);
    return wrap;
}

function buildEmptyState() {
    const wrap = document.createElement('div');
    wrap.className = 'empty-state';
    wrap.innerHTML = `
        <div class="empty-icon">✓</div>
        <h3>No vulnerabilities detected</h3>
        <p>Target passed the tested payloads &amp; header checks.</p>
    `;
    return wrap;
}

/* ───────────────────────── Error / helpers ───────────────────────── */

function showError(resultsDiv, vulnDiv, countBadge, message, target) {
    resultsDiv.style.display = 'block';
    countBadge.textContent = 'Error';
    countBadge.dataset.state = 'error';

    vulnDiv.replaceChildren();

    const wrap = document.createElement('div');
    wrap.className = 'empty-state error-state';

    const icon = document.createElement('div');
    icon.className = 'empty-icon';
    icon.textContent = '!';

    const h3 = document.createElement('h3');
    h3.textContent = 'Scan could not be completed';

    const p = document.createElement('p');
    p.textContent = message || 'Unknown error.';

    wrap.appendChild(icon);
    wrap.appendChild(h3);
    wrap.appendChild(p);

    if (target) {
        const targetLine = document.createElement('p');
        targetLine.style.marginTop = '8px';
        targetLine.style.fontFamily = 'var(--mono)';
        targetLine.style.fontSize = '12px';
        targetLine.style.color = 'var(--text-muted)';
        targetLine.textContent = target;
        wrap.appendChild(targetLine);
    }

    vulnDiv.appendChild(wrap);
}

function normalizeSeverity(sev) {
    const s = String(sev || '').trim();
    const map = {
        critical: 'High', high: 'High',
        medium: 'Medium', moderate: 'Medium',
        low: 'Low',
        info: 'Info', informational: 'Info', none: 'Info'
    };
    return map[s.toLowerCase()] || 'Info';
}

async function copyToClipboard(text, btn) {
    const original = btn.textContent;
    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
        } else {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
        }
        btn.textContent = 'Copied';
    } catch (_) {
        btn.textContent = 'Failed';
    }
    setTimeout(() => { btn.textContent = original; }, 1200);
}
