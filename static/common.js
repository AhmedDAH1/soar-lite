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
