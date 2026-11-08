// Shared helpers for the dashboard pages.
//
// Everything shown in this dashboard (alert titles, descriptions, IOC values,
// enrichment results) was written by whoever sent the alert, often an
// attacker: a phishing subject line or a scanner's User-Agent ends up here.
// Every value goes through esc() before it is put into HTML.

const API_BASE = '';

function esc(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function capitalize(text) {
    const s = String(text ?? '');
    return s.charAt(0).toUpperCase() + s.slice(1);
}

const SEVERITY_COLORS = {
    critical: 'bg-red-600',
    high: 'bg-orange-600',
    medium: 'bg-yellow-600',
    low: 'bg-blue-600'
};

const STATUS_COLORS = {
    new: 'bg-blue-600',
    investigating: 'bg-purple-600',
    contained: 'bg-orange-600',
    resolved: 'bg-green-600'
};

function getSeverityBadge(severity, size = 'text-xs px-2') {
    const color = SEVERITY_COLORS[severity] || 'bg-gray-600';
    return `<span class="${size} py-1 rounded font-semibold ${color}">${esc(String(severity ?? '').toUpperCase())}</span>`;
}

function getStatusBadge(status, size = 'text-xs px-2') {
    const color = STATUS_COLORS[status] || 'bg-gray-600';
    return `<span class="${size} py-1 rounded font-semibold ${color}">${esc(capitalize(status))}</span>`;
}

// The public demo is read-only: show a banner and hide controls that change data.
async function applyDemoMode() {
    try {
        const health = await (await fetch(`${API_BASE}/health`)).json();
        if (!health.demo_mode) return false;
        document.getElementById('demo-banner')?.classList.remove('hidden');
        document.querySelectorAll('[data-writes]').forEach(el => el.classList.add('hidden'));
        return true;
    } catch (error) {
        return false;
    }
}

// ── AI triage ──────────────────────────────────────────────────────
// The model only suggests. Its reasoning was influenced by alert text an
// attacker may have written, so it is escaped like everything else.

const VERDICTS = {
    true_positive: { label: 'Real attack', color: 'bg-red-700', text: 'text-red-300' },
    false_positive: { label: 'False alarm', color: 'bg-green-700', text: 'text-green-300' },
    needs_investigation: { label: 'Needs analyst', color: 'bg-yellow-700', text: 'text-yellow-300' }
};

// A small chip for the AI's suggestion; `triage` may be null (not triaged).
function getVerdictBadge(triage, size = 'text-xs px-2') {
    if (!triage) return `<span class="${size} py-1 rounded text-gray-500">—</span>`;
    if (triage.status === 'pending') {
        return `<span class="${size} py-1 rounded bg-gray-700 text-gray-300 inline-flex items-center gap-2"><span class="spinner spinner-sm"></span>Analysing</span>`;
    }
    if (triage.status === 'failed') {
        return `<span class="${size} py-1 rounded bg-gray-700 text-gray-300" title="The model gave no usable answer, so the incident goes to an analyst">AI failed: analyst</span>`;
    }
    if (triage.status !== 'done') return `<span class="${size} py-1 rounded text-gray-500">—</span>`;
    const v = VERDICTS[triage.verdict] || { label: triage.verdict, color: 'bg-gray-600' };
    const flag = triage.injection_suspected ? ' <span title="Possible prompt injection in the alert">⚠</span>' : '';
    const decided = triage.decision ? ` <span class="text-xs text-gray-300">· ${esc(triage.decision)}</span>` : '';
    return `<span class="${size} py-1 rounded font-semibold ${v.color}">${esc(v.label)}${flag}</span>${decided}`;
}

function percent(value) {
    return value == null ? '' : `${Math.round(value * 100)}%`;
}

function plural(count, word) {
    return `${count} ${word}${count === 1 ? '' : 's'}`;
}
