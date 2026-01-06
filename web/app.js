const API_BASE = '/api/v1';

let currentPage = 1;
const pageSize = 20;
let statusInterval = null;

document.addEventListener('DOMContentLoaded', () => {
    fetchStats();
    fetchScanStatus();
    fetchResults(1);
    fetchHistory();
    
    // Poll status every 2 seconds
    statusInterval = setInterval(() => {
        fetchScanStatus();
        fetchStats();
    }, 2000);
});

function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    
    document.getElementById(`tab-${tabId}`).classList.add('active');
    document.querySelector(`.tab-btn[onclick="switchTab('${tabId}')"]`).classList.add('active');
}

async function fetchStats() {
    try {
        const res = await fetch(`${API_BASE}/stats`);
        const data = await res.json();
        document.getElementById('stat-total').textContent = data.total_results || 0;
        document.getElementById('stat-unique').textContent = data.unique_open || 0;
        
        // Fetch top ports
        const portRes = await fetch(`${API_BASE}/stats/top-ports`);
        const portData = await portRes.json();
        if (portData && portData.length > 0) {
            document.getElementById('stat-top-port').textContent = `${portData[0].port} (${portData[0].count})`;
        }
    } catch (e) {
        console.error('Failed to fetch stats:', e);
    }
}

async function fetchScanStatus() {
    try {
        const res = await fetch(`${API_BASE}/scan/status`);
        const data = await res.json();
        
        const statusEl = document.getElementById('scan-status');
        const roundEl = document.getElementById('scan-round');
        const startBtn = document.getElementById('btn-start');
        const stopBtn = document.getElementById('btn-stop');
        
        statusEl.textContent = data.running ? 'Running' : 'Stopped';
        statusEl.style.color = data.running ? 'var(--success-color)' : 'var(--text-color)';
        roundEl.textContent = data.current_round || '-';
        
        startBtn.disabled = data.running;
        stopBtn.disabled = !data.running;
        
    } catch (e) {
        console.error('Failed to fetch status:', e);
    }
}

async function startScan() {
    if (!confirm('Start new scan?')) return;
    try {
        const res = await fetch(`${API_BASE}/scan/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}) // Send default config or form data
        });
        if (res.ok) {
            fetchScanStatus();
        } else {
            alert('Failed to start scan');
        }
    } catch (e) {
        alert('Error starting scan: ' + e.message);
    }
}

async function stopScan() {
    if (!confirm('Stop current scan?')) return;
    try {
        const res = await fetch(`${API_BASE}/scan/stop`, { method: 'POST' });
        if (res.ok) {
            fetchScanStatus();
        } else {
            alert('Failed to stop scan');
        }
    } catch (e) {
        alert('Error stopping scan: ' + e.message);
    }
}

async function fetchResults(page) {
    currentPage = page;
    try {
        const offset = (page - 1) * pageSize;
        const res = await fetch(`${API_BASE}/results?limit=${pageSize}&offset=${offset}`);
        const data = await res.json();
        
        const tbody = document.querySelector('#results-table tbody');
        tbody.innerHTML = '';
        
        if (data.results && data.results.length > 0) {
            data.results.forEach(item => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${item.ip}</td>
                    <td>${item.port}</td>
                    <td>${item.transport || 'TCP'}</td>
                    <td>${formatGeo(item)}</td>
                    <td>${item.round}</td>
                    <td>${new Date(item.timestamp * 1000).toLocaleString()}</td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center">No results found</td></tr>';
        }
        
        document.getElementById('page-info').textContent = `Page ${currentPage}`;
        
    } catch (e) {
        console.error('Failed to fetch results:', e);
    }
}

function formatGeo(item) {
    if (!item.country) return '-';
    let parts = [item.country];
    if (item.city) parts.push(item.city);
    return parts.join(', ');
}

function changePage(delta) {
    const newPage = currentPage + delta;
    if (newPage < 1) return;
    fetchResults(newPage);
}

async function fetchHistory() {
    try {
        const res = await fetch(`${API_BASE}/scan/history`);
        const data = await res.json();
        
        const tbody = document.querySelector('#history-table tbody');
        tbody.innerHTML = '';
        
        // Assuming history API returns a list
        if (Array.isArray(data)) {
            data.forEach(item => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${item.id || '-'}</td>
                    <td>${item.start_time ? new Date(item.start_time * 1000).toLocaleString() : '-'}</td>
                    <td>${item.end_time ? new Date(item.end_time * 1000).toLocaleString() : '-'}</td>
                    <td>${item.status || '-'}</td>
                    <td>${item.config || '-'}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.error('Failed to fetch history:', e);
    }
}

function exportData(format) {
    window.open(`${API_BASE}/export/${format}`, '_blank');
}
