const API_BASE = '/api/v1';

let currentPage = 1;
const pageSize = 20;
let statusInterval = null;

let lastScanRunning = false;

document.addEventListener('DOMContentLoaded', () => {
    fetchStats();
    fetchScanStatus();
    fetchResults(1);
    fetchHistory();
    
    // Poll status every 2 seconds
    statusInterval = setInterval(() => {
        fetchScanStatus();
        fetchStats();
        fetchResultsIfScanning();
    }, 2000);
});

function fetchResultsIfScanning() {
    fetchScanStatus().then(() => {
        const statusEl = document.getElementById('scan-status');
        const isRunning = statusEl.textContent === 'Running';
        
        // If scan started or stopped, refresh results
        if (isRunning !== lastScanRunning) {
            fetchResults(currentPage);
            lastScanRunning = isRunning;
        } else if (isRunning) {
            // While scanning, refresh results every 5 status polls (10 seconds)
            if (Math.random() < 0.2) {
                fetchResults(currentPage);
            }
        }
    }).catch(e => console.error('Failed to check scan status:', e));
}

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
        document.getElementById('stat-total').textContent = data.total_open_records || 0;
        document.getElementById('stat-unique').textContent = data.unique_ips || 0;
        
        // Fetch top ports
        const portRes = await fetch(`${API_BASE}/stats/top-ports`);
        const portData = await portRes.json();
        if (portData && portData.ports && portData.ports.length > 0) {
            document.getElementById('stat-top-port').textContent = `${portData.ports[0].port} (${portData.ports[0].open_count})`;
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
        
        statusEl.textContent = data.is_running ? 'Running' : 'Stopped';
        statusEl.style.color = data.is_running ? 'var(--success-color)' : 'var(--text-color)';
        roundEl.textContent = data.current_round || '-';
        
        startBtn.disabled = data.is_running;
        stopBtn.disabled = !data.is_running;
        
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
        const res = await fetch(`${API_BASE}/results?page=${page}&page_size=${pageSize}`);
        const data = await res.json();
        
        const tbody = document.querySelector('#results-table tbody');
        tbody.innerHTML = '';
        
        if (data.results && data.results.length > 0) {
            data.results.forEach(item => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${item.ip_address}</td>
                    <td>${item.port}</td>
                    <td>${item.ip_type || 'TCP'}</td>
                    <td>-</td>
                    <td>${item.scan_round}</td>
                    <td>${new Date(item.first_seen).toLocaleString()}</td>
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
        
        // API returns { scans: [...] }
        if (data.scans && Array.isArray(data.scans)) {
            data.scans.forEach(item => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${item.round || '-'}</td>
                    <td>${item.start_time ? new Date(item.start_time).toLocaleString() : '-'}</td>
                    <td>${item.end_time ? new Date(item.end_time).toLocaleString() : '-'}</td>
                    <td>Completed</td>
                    <td>${item.total_open_ports || 0} open ports, ${item.ports_scanned || 0} scanned</td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center">No history found</td></tr>';
        }
    } catch (e) {
        console.error('Failed to fetch history:', e);
    }
}

function exportData(format) {
    window.open(`${API_BASE}/export/${format}`, '_blank');
}
