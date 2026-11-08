// Incident detail page. Helpers (esc, badges, dates) are in common.js.
// Every value from the API is escaped with esc() before it goes into HTML.

let currentIncident = null;
let incidentId = null;
let demoMode = false;
let aiStatus = null;
let aiPoll = null;

// Incident IDs are numbers; anything else in the URL is ignored.
function getIncidentId() {
    const id = new URLSearchParams(window.location.search).get('id');
    return /^\d+$/.test(id || '') ? id : null;
}

// Show/hide tabs
function showTab(tabName) {
    ['alerts', 'iocs', 'timeline'].forEach(tab => {
        const button = document.getElementById(`tab-${tab}`);
        const content = document.getElementById(`content-${tab}`);

        if (tab === tabName) {
            button.classList.add('border-blue-500', 'text-blue-400');
            button.classList.remove('border-transparent', 'text-gray-400');
            content.classList.remove('hidden');
        } else {
            button.classList.remove('border-blue-500', 'text-blue-400');
            button.classList.add('border-transparent', 'text-gray-400');
            content.classList.add('hidden');
        }
    });
}

// Load incident details
async function loadIncident() {
    incidentId = getIncidentId();

    if (!incidentId) {
        window.location.href = '/';
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/incidents/${incidentId}`);

        if (!response.ok) {
            throw new Error('Incident not found');
        }

        currentIncident = await response.json();

        // Header: textContent never interprets HTML
        document.getElementById('incident-title').textContent = `#${currentIncident.id} ${currentIncident.title}`;
        document.getElementById('incident-severity-badge').innerHTML = getSeverityBadge(currentIncident.severity, 'text-sm px-3');
        document.getElementById('incident-status-badge').innerHTML = getStatusBadge(currentIncident.status, 'text-sm px-3');
        document.getElementById('incident-description').textContent = currentIncident.description || 'No description';
        document.getElementById('incident-created').textContent = formatDate(currentIncident.created_at);
        document.getElementById('incident-updated').textContent = formatDate(currentIncident.updated_at);

        renderActionButtons();
        renderAI();
        renderAlerts();
        renderIOCs();
        renderTimeline();

    } catch (error) {
        console.error('Error loading incident:', error);
        document.getElementById('incident-title').textContent = 'Incident not found';
    }
}

// Render action buttons based on current status
function renderActionButtons() {
    const container = document.getElementById('action-buttons');
    if (demoMode) {
        container.innerHTML = '';
        return;
    }

    const validTransitions = {
        'new': ['investigating'],
        'investigating': ['investigating', 'contained'],
        'contained': ['resolved'],
        'resolved': []
    };

    const nextStates = validTransitions[currentIncident.status] || [];
    const buttonsHtml = nextStates
        .filter(state => state !== currentIncident.status)
        .map(state => `
            <button data-status="${esc(state)}"
                    class="bg-green-600 hover:bg-green-700 px-4 py-2 rounded text-sm">
                Mark as ${esc(capitalize(state))}
            </button>
        `).join('');

    container.innerHTML = buttonsHtml || '<span class="text-gray-500">No actions available (incident resolved)</span>';
}

// Render alerts
function renderAlerts() {
    const alertsHtml = currentIncident.alerts.map(alert => `
        <div class="bg-gray-700 rounded p-4 mb-3">
            <div class="flex justify-between items-start mb-2">
                <div class="font-medium">${esc(alert.title)}</div>
                <span class="text-xs px-2 py-1 bg-gray-600 rounded">${esc(String(alert.source).toUpperCase())}</span>
            </div>
            ${alert.description ? `<p class="text-sm text-gray-300 mb-2">${esc(alert.description)}</p>` : ''}
            <div class="text-xs text-gray-400">${esc(formatDate(alert.created_at))}</div>
        </div>
    `).join('');

    document.getElementById('alerts-list').innerHTML = alertsHtml || '<p class="text-gray-500">No alerts</p>';
}

function enrichmentSummary(ioc) {
    if (!ioc.enrichment_data) return 'Not enriched';
    try {
        const data = typeof ioc.enrichment_data === 'string'
            ? JSON.parse(ioc.enrichment_data)
            : ioc.enrichment_data;

        const parts = [];
        if (data.virustotal) {
            parts.push(`VT: ${data.virustotal.malicious || 0} detections`);
        }
        if (data.abuseipdb) {
            parts.push(`Abuse: ${data.abuseipdb.abuse_confidence_score}% confidence`);
        }
        if (data.geolocation) {
            parts.push(`${data.geolocation.country || 'Unknown'}`);
        }
        return parts.join(' | ') || 'Enriched';
    } catch (e) {
        return 'Parse error';
    }
}

// Render IOCs
function renderIOCs() {
    if (currentIncident.iocs.length === 0) {
        document.getElementById('iocs-table').innerHTML = '<p class="text-gray-500">No IOCs extracted</p>';
        return;
    }

    const rows = currentIncident.iocs.map(ioc => `
        <tr class="hover:bg-gray-700">
            <td class="py-3">
                <span class="px-2 py-1 bg-gray-600 rounded text-xs">${esc(String(ioc.type).toUpperCase())}</span>
            </td>
            <td class="py-3 font-mono text-xs">${esc(ioc.value)}</td>
            <td class="py-3">
                ${ioc.is_malicious
                    ? '<span class="text-red-400">✗ Malicious</span>'
                    : '<span class="text-green-400">✓ Clean</span>'}
            </td>
            <td class="py-3 text-gray-400">${esc(ioc.extracted_from || 'N/A')}</td>
            <td class="py-3 text-gray-400 text-xs">${esc(enrichmentSummary(ioc))}</td>
        </tr>
    `).join('');

    document.getElementById('iocs-table').innerHTML = `
        <table class="w-full text-sm">
            <thead class="text-left text-gray-400 border-b border-gray-600">
                <tr>
                    <th class="pb-2">Type</th>
                    <th class="pb-2">Value</th>
                    <th class="pb-2">Malicious</th>
                    <th class="pb-2">Source</th>
                    <th class="pb-2">Enrichment</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-700">${rows}</tbody>
        </table>
    `;
}

// Render timeline
function renderTimeline() {
    if (currentIncident.actions.length === 0) {
        document.getElementById('timeline-list').innerHTML = '<p class="text-gray-500">No actions recorded</p>';
        return;
    }

    const timelineHtml = currentIncident.actions.map((action, index) => {
        const isSystem = action.performed_by === 'system';
        const iconColor = isSystem ? 'bg-blue-600' : 'bg-green-600';
        const icon = isSystem ? '⚙️' : '👤';

        return `
            <div class="flex mb-6">
                <div class="flex flex-col items-center mr-4">
                    <div class="${iconColor} rounded-full w-8 h-8 flex items-center justify-center text-sm">
                        ${icon}
                    </div>
                    ${index < currentIncident.actions.length - 1 ? '<div class="w-px h-full bg-gray-600 mt-2"></div>' : ''}
                </div>
                <div class="flex-1">
                    <div class="bg-gray-700 rounded p-4">
                        <div class="flex justify-between items-start mb-2">
                            <div class="font-medium">${esc(action.description)}</div>
                            <span class="text-xs text-gray-400">${esc(formatDate(action.created_at))}</span>
                        </div>
                        <div class="text-sm text-gray-400">
                            ${action.playbook_name
                                ? `<span class="px-2 py-1 bg-purple-600 rounded text-xs mr-2">Playbook: ${esc(action.playbook_name)}</span>`
                                : ''}
                            <span class="text-xs">by ${esc(action.performed_by)}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }).join('');

    document.getElementById('timeline-list').innerHTML = timelineHtml;
}

// Update incident status
async function updateStatus(newStatus) {
    if (!confirm(`Change status to ${newStatus}?`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/incidents/${incidentId}?analyst_username=web_user`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                status: newStatus
            })
        });

        if (!response.ok) {
            throw new Error('Failed to update status');
        }

        location.reload();

    } catch (error) {
        console.error('Error updating status:', error);
        alert('Failed to update status');
    }
}

// Enrich incident IOCs
async function enrichIncident(button) {
    if (!confirm('Enrich all IOCs? This may take 10-15 seconds.')) {
        return;
    }

    button.disabled = true;
    button.textContent = '⏳ Enriching...';

    try {
        const response = await fetch(`${API_BASE}/api/enrichment/incident/${incidentId}`, {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error('Enrichment failed');
        }

        location.reload();

    } catch (error) {
        console.error('Error enriching:', error);
        alert('Enrichment failed');
        button.disabled = false;
        button.textContent = '🔍 Enrich IOCs';
    }
}

// Download report
function downloadReport(format) {
    window.open(`${API_BASE}/api/reports/incident/${incidentId}/${format}`, '_blank', 'noopener');
}

// ── AI triage panel ───────────────────────────────────────────────

function aiButton(action, label, classes) {
    return `<button data-ai="${esc(action)}" data-writes class="${classes} px-4 py-2 rounded text-sm">${esc(label)}</button>`;
}

function contextList(context) {
    const entries = Object.entries(context || {});
    if (!entries.length) return '<p class="text-gray-400 text-sm">None: the SOC has no record of these addresses or senders.</p>';
    return `<dl class="grid grid-cols-1 md:grid-cols-4 gap-x-4 gap-y-2 text-sm">${entries.map(([k, v]) => `
        <dt class="font-mono text-gray-400">${esc(k)}</dt>
        <dd class="md:col-span-3">${esc(typeof v === 'object' ? Object.entries(v).map(([a, b]) => `${a}: ${b}`).join(' · ') : v)}</dd>`).join('')}</dl>`;
}

function renderAI() {
    const panel = document.getElementById('ai-panel');
    const t = currentIncident.triage;
    clearTimeout(aiPoll);
    const configured = aiStatus && aiStatus.configured;
    const header = (right) => `
        <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-4">
            <div>
                <h2 class="text-xl font-semibold">AI triage</h2>
                <p class="text-xs text-gray-400 mt-1">The model only suggests. It can't change this incident; you accept or reject.</p>
            </div>
            <div class="flex gap-2 items-center">${right}</div>
        </div>`;

    if (!t) {
        panel.innerHTML = header(configured && !demoMode ? aiButton('run', 'Ask the AI', 'bg-blue-600 hover:bg-blue-700') : '') +
            `<p class="text-gray-400">${configured ? 'Not triaged yet.' : `AI triage is off. ${esc(aiStatus ? aiStatus.problem : '')}`}</p>`;
        return;
    }
    const model = `<span class="text-xs px-2 py-1 rounded bg-gray-700 text-gray-300">${esc(t.model || 'model')} · ${esc(t.mode)} mode</span>`;
    if (t.status === 'pending') {
        panel.innerHTML = header(model) + '<p class="text-gray-300 flex items-center gap-3"><span class="spinner spinner-sm"></span>The model is reading the alert. A local model can take a minute.</p>';
        aiPoll = setTimeout(loadIncident, 2500);
        return;
    }
    if (t.status !== 'done') {
        panel.innerHTML = header(model + (configured && !demoMode ? aiButton('run', 'Try again', 'bg-gray-600 hover:bg-gray-700') : '')) +
            `<p class="text-gray-300">No usable answer from the model, so this incident goes to an analyst. <span class="text-gray-400">${esc(t.error || '')}</span></p>`;
        return;
    }

    const v = VERDICTS[t.verdict] || { label: t.verdict, color: 'bg-gray-600' };
    let decision = '';
    if (t.decision) {
        decision = `<span class="text-sm text-gray-300">${esc(capitalize(t.decision))} by ${esc(t.decided_by)}</span>`;
    } else if (!demoMode) {
        const accept = t.verdict === 'false_positive' ? 'Accept: close as false alarm'
            : t.verdict === 'true_positive' ? `Accept: real attack, ${t.severity}` : 'Accept: investigate';
        decision = aiButton('accept', accept, 'bg-green-600 hover:bg-green-700') + aiButton('reject', 'Reject', 'bg-gray-600 hover:bg-gray-700');
    }
    const rerun = configured && !demoMode && !t.decision ? aiButton('run', 'Re-run', 'bg-gray-700 hover:bg-gray-600') : '';

    panel.innerHTML = header(model + rerun) + `
        ${t.injection_suspected ? `<div class="mb-4 rounded border border-yellow-700 bg-yellow-900 bg-opacity-40 px-4 py-3 text-sm text-yellow-200">
            ⚠ Possible prompt injection: text in this alert tries to instruct the AI${t.model_flagged_injection ? ' (the model reported it)' : ' (caught by the guards)'}.
            Treat the attempt itself as a sign the sender is malicious.</div>` : ''}
        <div class="flex flex-wrap items-center gap-3 mb-3">
            <span class="text-lg px-3 py-1 rounded font-bold ${v.color}">${esc(v.label)}</span>
            ${getSeverityBadge(t.severity, 'text-sm px-3')}
            <span class="text-sm text-gray-300">${esc(percent(t.confidence))} confident</span>
        </div>
        <p class="text-gray-200 mb-4">${esc(t.reasoning)}</p>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-4">
            <div>
                <h3 class="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-2">Suggested next steps</h3>
                <ul class="list-disc ml-5 text-sm space-y-1">${(t.next_steps || []).map(s => `<li>${esc(s)}</li>`).join('') || '<li class="text-gray-400">None</li>'}</ul>
            </div>
            <div>
                <h3 class="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-2">Records the AI cited</h3>
                <p class="text-sm">${(t.evidence || []).length ? esc(t.evidence.join(', ')) : '<span class="text-gray-400">None</span>'}</p>
                ${(t.overrides || []).map(o => `<div class="mt-2 text-sm rounded bg-blue-900 bg-opacity-50 border border-blue-800 px-3 py-2 text-blue-200">Guard: ${esc(o)}</div>`).join('')}
            </div>
        </div>
        <details class="mb-4">
            <summary class="text-sm text-gray-400 hover:text-gray-200">Trusted records the AI was given (from the SOC's files, not the alert)</summary>
            <div class="mt-3">${contextList(t.context)}</div>
        </details>
        <div class="flex flex-wrap gap-2 items-center border-t border-gray-700 pt-4">${decision}</div>`;
}

async function aiAction(action, button) {
    button.disabled = true;
    try {
        const url = action === 'run'
            ? `${API_BASE}/api/triage/incident/${incidentId}`
            : `${API_BASE}/api/triage/incident/${incidentId}/decision?analyst_username=web_user`;
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: action === 'run' ? '{}' : JSON.stringify({ decision: action })
        });
        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(typeof data.detail === 'string' ? data.detail : 'Request failed');
        }
        await loadIncident();
    } catch (error) {
        alert(error.message);
        button.disabled = false;
    }
}

// Initialize: no inline handlers (the Content-Security-Policy blocks them)
document.addEventListener('DOMContentLoaded', async () => {
    document.querySelectorAll('[data-tab]').forEach(button => {
        button.addEventListener('click', () => showTab(button.dataset.tab));
    });
    document.querySelectorAll('[data-report]').forEach(button => {
        button.addEventListener('click', () => downloadReport(button.dataset.report));
    });
    document.getElementById('enrich-iocs').addEventListener('click', event => enrichIncident(event.currentTarget));
    document.getElementById('action-buttons').addEventListener('click', event => {
        const button = event.target.closest('button[data-status]');
        if (button) updateStatus(button.dataset.status);
    });

    document.getElementById('ai-panel').addEventListener('click', event => {
        const button = event.target.closest('button[data-ai]');
        if (button) aiAction(button.dataset.ai, button);
    });

    demoMode = await applyDemoMode();
    try {
        aiStatus = await (await fetch(`${API_BASE}/api/triage/status`)).json();
    } catch (error) {
        aiStatus = null;
    }
    loadIncident();
});
