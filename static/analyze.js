// Analyze page: upload files, send them for analysis, follow AI triage as it runs.
// Helpers (esc, badges, dates) are in common.js. File names and contents are
// the user's, and everything the API returns was shaped by alert text, so all
// of it is escaped.

const files = [];          // {name, content}
let incidentIds = [];
let pollTimer = null;

function setError(message) {
    const box = document.getElementById('upload-error');
    box.textContent = message || '';
    box.classList.toggle('hidden', !message);
}

function formatSize(bytes) {
    return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`;
}

function renderFiles() {
    const list = document.getElementById('file-list');
    list.innerHTML = files.map((f, i) => `
        <li class="flex items-center justify-between py-2 text-sm">
            <span><span class="font-mono">${esc(f.name)}</span>
                <span class="text-gray-400 ml-2">${esc(formatSize(new Blob([f.content]).size))} · ${esc(f.name.toLowerCase().endsWith('.eml') ? 'email' : 'log')}</span></span>
            <button class="text-gray-400 hover:text-red-300" data-remove="${i}" aria-label="Remove ${esc(f.name)}">Remove</button>
        </li>`).join('');
    document.getElementById('analyze').disabled = files.length === 0;
}

async function addFiles(fileList) {
    setError('');
    for (const file of fileList) {
        if (files.length >= 20) { setError('At most 20 files at a time.'); break; }
        if (file.size > 5 * 1024 * 1024) { setError(`${file.name} is larger than 5 MB.`); continue; }
        const content = await file.text();
        const existing = files.findIndex(f => f.name === file.name);
        if (existing >= 0) files[existing] = { name: file.name, content };
        else files.push({ name: file.name, content });
    }
    renderFiles();
}

async function loadDemo() {
    setError('');
    const response = await fetch(`${API_BASE}/api/analyze/samples`);
    const samples = await response.json();
    files.length = 0;
    files.push(...samples);
    renderFiles();
}

async function loadStatus() {
    try {
        const s = await (await fetch(`${API_BASE}/api/analyze/status`)).json();
        const up = (ok, text) => `<span class="${ok ? 'text-green-400' : 'text-red-300'}">● ${esc(text)}</span>`;
        document.getElementById('status-logs').innerHTML = up(s.logs.up, s.logs.up ? 'ready' : `not reachable at ${s.logs.url}`);
        document.getElementById('status-email').innerHTML = up(s.email.up, s.email.up ? 'ready' : `not reachable at ${s.email.url}`);
        document.getElementById('status-context').textContent = `${plural(s.context.hosts, 'host')} and ${plural(s.context.domains, 'sender')} on record`;
        document.getElementById('ai-model').textContent = s.ai.configured ? s.ai.model : 'AI triage';
        document.getElementById('status-ai').innerHTML = s.ai.configured
            ? up(true, `ready · ${s.ai.mode} mode${s.ai.local ? ' · runs locally' : ''}`)
            : `<span class="text-yellow-300">● off: ${esc(s.ai.problem)}</span>`;
    } catch (error) {
        console.error('Status check failed', error);
    }
}

async function analyze() {
    setError('');
    const button = document.getElementById('analyze');
    button.disabled = true;
    button.innerHTML = '<span class="spinner spinner-sm mr-2"></span>Analyzing…';
    try {
        const response = await fetch(`${API_BASE}/api/analyze/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ files })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Analysis failed');
        showResults(data);
    } catch (error) {
        setError(error.message);
    } finally {
        button.textContent = 'Analyze';
        button.disabled = files.length === 0;
    }
}

function showResults(data) {
    document.getElementById('results').classList.remove('hidden');
    document.getElementById('sum-files').textContent = data.files.filter(f => f.kind !== 'correlation').length;
    document.getElementById('sum-incidents').textContent = data.incidents.length;
    document.getElementById('file-results').innerHTML = data.files.map(f => `
        <tr>
            <td class="px-6 py-3 font-mono">${esc(f.name)}</td>
            <td class="px-6 py-3">${esc(f.type || 'not recognised')}${f.verdict ? ` <span class="text-gray-400">· ${esc(f.verdict)}</span>` : ''}</td>
            <td class="px-6 py-3">${f.entries == null ? '—' : esc(f.entries)}</td>
            <td class="px-6 py-3">${f.detections ? `<span class="font-semibold">${esc(f.detections)}</span>` : '<span class="text-gray-400">none</span>'}</td>
        </tr>`).join('');
    incidentIds = data.incidents.map(i => i.id);
    if (!incidentIds.length) {
        document.getElementById('incident-results').innerHTML =
            '<tr><td colspan="4" class="px-6 py-6 text-center text-gray-400">No threats found in these files, so no incidents were opened.</td></tr>';
    }
    refreshIncidents();
    document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}

function why(t) {
    if (!t) return '<span class="text-gray-500">AI triage is off</span>';
    if (t.status === 'pending') return '<span class="text-gray-400">The model is reading the alert…</span>';
    if (t.status === 'failed') return `<span class="text-gray-400">${esc(t.error || 'No usable answer')}</span>`;
    const parts = [];
    if (t.injection_suspected) parts.push('<div class="text-yellow-300">⚠ Text in the alert tries to instruct the AI</div>');
    if (t.overrides && t.overrides.length) parts.push(`<div class="text-blue-300">Guard: ${esc(t.overrides[0])}</div>`);
    if (t.evidence && t.evidence.length && t.verdict === 'false_positive') {
        parts.push(`<div class="text-green-300">Cites the SOC's records: ${esc(t.evidence.join(', '))}</div>`);
    }
    const reasoning = String(t.reasoning || '');
    parts.push(`<div class="text-gray-300">${esc(reasoning.length > 220 ? reasoning.slice(0, 220) + '…' : reasoning)}</div>`);
    return parts.join('');
}

async function refreshIncidents() {
    clearTimeout(pollTimer);
    if (!incidentIds.length) return;
    const incidents = await Promise.all(incidentIds.map(async id => {
        const r = await fetch(`${API_BASE}/api/incidents/${id}`);
        return r.ok ? r.json() : null;
    }));
    const rows = incidents.filter(Boolean);
    document.getElementById('incident-results').innerHTML = rows.map(i => `
        <tr class="align-top">
            <td class="px-6 py-3"><a class="font-medium hover:text-blue-300" href="/static/incident.html?id=${encodeURIComponent(i.id)}">#${esc(i.id)} ${esc(i.title)}</a></td>
            <td class="px-6 py-3">${getSeverityBadge(i.severity)}</td>
            <td class="px-6 py-3 whitespace-nowrap">${getVerdictBadge(i.triage)}${i.triage && i.triage.confidence != null ? `<div class="text-xs text-gray-400 mt-1">${esc(percent(i.triage.confidence))} confident</div>` : ''}</td>
            <td class="px-6 py-3 max-w-md">${why(i.triage)}</td>
        </tr>`).join('');

    const done = rows.filter(i => i.triage && i.triage.status === 'done');
    const pending = rows.filter(i => i.triage && i.triage.status === 'pending').length;
    document.getElementById('sum-attacks').textContent = done.filter(i => i.triage.verdict === 'true_positive').length;
    document.getElementById('sum-false').textContent = done.filter(i => i.triage.verdict === 'false_positive').length;
    document.getElementById('sum-injection').textContent = rows.filter(i => i.triage && i.triage.injection_suspected).length;
    const progress = document.getElementById('ai-progress');
    const anyTriage = rows.some(i => i.triage);
    progress.textContent = !anyTriage ? 'AI triage is off: set a model to get suggestions'
        : pending ? `AI is triaging: ${rows.length - pending} of ${rows.length} done`
        : 'AI triage finished. Open an incident to accept or reject its suggestion.';
    if (pending) pollTimer = setTimeout(refreshIncidents, 2500);
}

document.addEventListener('DOMContentLoaded', async () => {
    const input = document.getElementById('file-input');
    const zone = document.getElementById('dropzone');
    input.addEventListener('change', () => { addFiles(input.files); input.value = ''; });
    ['dragenter', 'dragover'].forEach(type => zone.addEventListener(type, e => { e.preventDefault(); zone.classList.add('dragging'); }));
    ['dragleave', 'drop'].forEach(type => zone.addEventListener(type, e => { e.preventDefault(); zone.classList.remove('dragging'); }));
    zone.addEventListener('drop', e => addFiles(e.dataTransfer.files));
    document.getElementById('file-list').addEventListener('click', e => {
        const button = e.target.closest('button[data-remove]');
        if (button) { files.splice(Number(button.dataset.remove), 1); renderFiles(); }
    });
    document.getElementById('load-demo').addEventListener('click', loadDemo);
    document.getElementById('clear-files').addEventListener('click', () => { files.length = 0; setError(''); renderFiles(); });
    document.getElementById('analyze').addEventListener('click', analyze);
    await applyDemoMode();
    loadStatus();
});
