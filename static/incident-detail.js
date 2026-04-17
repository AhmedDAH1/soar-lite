const API_BASE = '';
let currentIncident = null;
let incidentId = null;

// Get incident ID from URL
function getIncidentId() {
    const params = new URLSearchParams(window.location.search);
    return params.get('id');
}

// Format date
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

// Severity badge
function getSeverityBadge(severity) {
    const colors = {
        critical: 'bg-red-600',
        high: 'bg-orange-600',
        medium: 'bg-yellow-600',
        low: 'bg-blue-600'
    };
    return `<span class="px-3 py-1 rounded text-sm font-semibold ${colors[severity]}">${severity.toUpperCase()}</span>`;
}

// Status badge
function getStatusBadge(status) {
    const colors = {
        new: 'bg-blue-600',
        investigating: 'bg-purple-600',
        contained: 'bg-orange-600',
        resolved: 'bg-green-600'
    };
    return `<span class="px-3 py-1 rounded text-sm font-semibold ${colors[status]}">${status.charAt(0).toUpperCase() + status.slice(1)}</span>`;
}

// Show/hide tabs
function showTab(tabName) {
    // Update tab buttons
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
        alert('No incident ID provided');
        window.location.href = '/';
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/api/incidents/${incidentId}`);
        
        if (!response.ok) {
            throw new Error('Incident not found');
        }
        
        currentIncident = await response.json();
        
        // Update header
        document.getElementById('incident-title').textContent = `#${currentIncident.id} ${currentIncident.title}`;
        document.getElementById('incident-severity-badge').innerHTML = getSeverityBadge(currentIncident.severity);
        document.getElementById('incident-status-badge').innerHTML = getStatusBadge(currentIncident.status);
        document.getElementById('incident-description').textContent = currentIncident.description || 'No description';
        document.getElementById('incident-created').textContent = formatDate(currentIncident.created_at);
        document.getElementById('incident-updated').textContent = formatDate(currentIncident.updated_at);
        
        // Render action buttons
        renderActionButtons();
        
        // Render tabs
        renderAlerts();
        renderIOCs();
        renderTimeline();
        
    } catch (error) {
        console.error('Error loading incident:', error);
        alert('Failed to load incident');
        window.location.href = '/';
    }
}

// Render action buttons based on current status
function renderActionButtons() {
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
            <button onclick="updateStatus('${state}')" 
                    class="bg-green-600 hover:bg-green-700 px-4 py-2 rounded text-sm">
                Mark as ${state.charAt(0).toUpperCase() + state.slice(1)}
            </button>
        `).join('');
    
    document.getElementById('action-buttons').innerHTML = buttonsHtml || '<span class="text-gray-500">No actions available (incident resolved)</span>';
}

// Render alerts
function renderAlerts() {
    const alertsHtml = currentIncident.alerts.map(alert => `
        <div class="bg-gray-700 rounded p-4 mb-3">
            <div class="flex justify-between items-start mb-2">
                <div class="font-medium">${alert.title}</div>
                <span class="text-xs px-2 py-1 bg-gray-600 rounded">${alert.source.toUpperCase()}</span>
            </div>
            ${alert.description ? `<p class="text-sm text-gray-300 mb-2">${alert.description}</p>` : ''}
            <div class="text-xs text-gray-400">${formatDate(alert.created_at)}</div>
        </div>
    `).join('');
    
    document.getElementById('alerts-list').innerHTML = alertsHtml || '<p class="text-gray-500">No alerts</p>';
}

// Render IOCs
function renderIOCs() {
    if (currentIncident.iocs.length === 0) {
        document.getElementById('iocs-table').innerHTML = '<p class="text-gray-500">No IOCs extracted</p>';
        return;
    }
    
    const tableHtml = `
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
            <tbody class="divide-y divide-gray-700">
                ${currentIncident.iocs.map(ioc => {
                    let enrichmentSummary = 'Not enriched';
                    
                    if (ioc.enrichment_data) {
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
                            
                            enrichmentSummary = parts.join(' | ') || 'Enriched';
                        } catch (e) {
                            enrichmentSummary = 'Parse error';
                        }
                    }
                    
                    return `
                        <tr class="hover:bg-gray-700">
                            <td class="py-3">
                                <span class="px-2 py-1 bg-gray-600 rounded text-xs">${ioc.type.toUpperCase()}</span>
                            </td>
                            <td class="py-3 font-mono text-xs">${ioc.value}</td>
                            <td class="py-3">
                                ${ioc.is_malicious 
                                    ? '<span class="text-red-400">✗ Malicious</span>' 
                                    : '<span class="text-green-400">✓ Clean</span>'}
                            </td>
                            <td class="py-3 text-gray-400">${ioc.extracted_from || 'N/A'}</td>
                            <td class="py-3 text-gray-400 text-xs">${enrichmentSummary}</td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
    
    document.getElementById('iocs-table').innerHTML = tableHtml;
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
                            <div class="font-medium">${action.description}</div>
                            <span class="text-xs text-gray-400">${formatDate(action.created_at)}</span>
                        </div>
                        <div class="text-sm text-gray-400">
                            ${action.playbook_name 
                                ? `<span class="px-2 py-1 bg-purple-600 rounded text-xs mr-2">Playbook: ${action.playbook_name}</span>` 
                                : ''}
                            <span class="text-xs">by ${action.performed_by}</span>
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
        
        alert('Status updated successfully!');
        location.reload();
        
    } catch (error) {
        console.error('Error updating status:', error);
        alert('Failed to update status');
    }
}

// Enrich incident IOCs
async function enrichIncident() {
    if (!confirm('Enrich all IOCs? This may take 10-15 seconds.')) {
        return;
    }
    
    const button = event.target;
    button.disabled = true;
    button.textContent = '⏳ Enriching...';
    
    try {
        const response = await fetch(`${API_BASE}/api/enrichment/incident/${incidentId}`, {
            method: 'POST'
        });
        
        if (!response.ok) {
            throw new Error('Enrichment failed');
        }
        
        alert('IOCs enriched successfully!');
        location.reload();
        
    } catch (error) {
        console.error('Error enriching:', error);
        alert('Enrichment failed');
        button.disabled = false;
        button.textContent = '🔍 Enrich IOCs';
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', loadIncident);