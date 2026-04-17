// API Base URL
const API_BASE = '';

// Utility: Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Utility: Get severity badge HTML
function getSeverityBadge(severity) {
    const colors = {
        critical: 'bg-red-600',
        high: 'bg-orange-600',
        medium: 'bg-yellow-600',
        low: 'bg-blue-600'
    };
    
    return `<span class="px-2 py-1 rounded text-xs font-semibold ${colors[severity] || 'bg-gray-600'}">${severity.toUpperCase()}</span>`;
}

// Utility: Get status badge HTML
function getStatusBadge(status) {
    const colors = {
        new: 'bg-blue-600',
        investigating: 'bg-purple-600',
        contained: 'bg-orange-600',
        resolved: 'bg-green-600'
    };
    
    return `<span class="px-2 py-1 rounded text-xs font-semibold ${colors[status] || 'bg-gray-600'}">${status.charAt(0).toUpperCase() + status.slice(1)}</span>`;
}

// Update clock
function updateClock() {
    const now = new Date();
    document.getElementById('clock').textContent = now.toLocaleTimeString('en-US');
}
setInterval(updateClock, 1000);
updateClock();

// Load statistics
async function loadStatistics() {
    try {
        const response = await fetch(`${API_BASE}/api/incidents/statistics`);
        const stats = await response.json();
        
        // Update metric cards
        document.getElementById('total-incidents').textContent = stats.total_incidents;
        document.getElementById('unresolved').textContent = stats.unresolved;
        document.getElementById('critical-unresolved').textContent = stats.critical_unresolved;
        document.getElementById('recent-7days').textContent = stats.recent_7_days;
        
        // Update charts
        updateSeverityChart(stats.by_severity);
        updateStatusChart(stats.by_status);
        
    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

// Update severity chart
let severityChart = null;
function updateSeverityChart(data) {
    const ctx = document.getElementById('severityChart');
    
    if (severityChart) {
        severityChart.destroy();
    }
    
    severityChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [
                    data.critical || 0,
                    data.high || 0,
                    data.medium || 0,
                    data.low || 0
                ],
                backgroundColor: [
                    'rgba(239, 68, 68, 0.8)',   // red
                    'rgba(249, 115, 22, 0.8)',  // orange
                    'rgba(234, 179, 8, 0.8)',   // yellow
                    'rgba(59, 130, 246, 0.8)'   // blue
                ],
                borderColor: 'rgba(31, 41, 55, 1)',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: {
                        color: 'rgba(156, 163, 175, 1)'
                    }
                }
            }
        }
    });
}

// Update status chart
let statusChart = null;
function updateStatusChart(data) {
    const ctx = document.getElementById('statusChart');
    
    if (statusChart) {
        statusChart.destroy();
    }
    
    statusChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['New', 'Investigating', 'Contained', 'Resolved'],
            datasets: [{
                label: 'Incidents',
                data: [
                    data.new || 0,
                    data.investigating || 0,
                    data.contained || 0,
                    data.resolved || 0
                ],
                backgroundColor: [
                    'rgba(59, 130, 246, 0.8)',  // blue
                    'rgba(168, 85, 247, 0.8)',  // purple
                    'rgba(249, 115, 22, 0.8)',  // orange
                    'rgba(34, 197, 94, 0.8)'    // green
                ],
                borderColor: 'rgba(31, 41, 55, 1)',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: 'rgba(156, 163, 175, 1)',
                        stepSize: 1
                    },
                    grid: {
                        color: 'rgba(55, 65, 81, 0.5)'
                    }
                },
                x: {
                    ticks: {
                        color: 'rgba(156, 163, 175, 1)'
                    },
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

// Load incidents list
async function loadIncidents() {
    const severity = document.getElementById('filter-severity').value;
    const status = document.getElementById('filter-status').value;
    const search = document.getElementById('filter-search').value;
    
    // Build query params
    const params = new URLSearchParams();
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);
    if (search) params.append('search', search);
    params.append('limit', '50');
    
    try {
        const response = await fetch(`${API_BASE}/api/incidents?${params}`);
        const incidents = await response.json();
        
        const tbody = document.getElementById('incidents-table');
        
        if (incidents.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="px-6 py-8 text-center text-gray-500">
                        No incidents found
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = incidents.map(incident => `
            <tr class="hover:bg-gray-750 cursor-pointer" onclick="window.location.href='/static/incident.html?id=${incident.id}'">
                <td class="px-6 py-4 text-sm">#${incident.id}</td>
                <td class="px-6 py-4">
                    <div class="font-medium">${incident.title}</div>
                    ${incident.description ? `<div class="text-sm text-gray-400 truncate max-w-md">${incident.description.substring(0, 80)}...</div>` : ''}
                </td>
                <td class="px-6 py-4">${getSeverityBadge(incident.severity)}</td>
                <td class="px-6 py-4">${getStatusBadge(incident.status)}</td>
                <td class="px-6 py-4 text-sm text-gray-400">${formatDate(incident.created_at)}</td>
            </tr>
        `).join('');
        
    } catch (error) {
        console.error('Error loading incidents:', error);
        document.getElementById('incidents-table').innerHTML = `
            <tr>
                <td colspan="5" class="px-6 py-8 text-center text-red-400">
                    Error loading incidents
                </td>
            </tr>
        `;
    }
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    loadStatistics();
    loadIncidents();
    
    // Refresh every 30 seconds
    setInterval(() => {
        loadStatistics();
        loadIncidents();
    }, 30000);
});