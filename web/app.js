const API_BASE = '/api/v1';

// --- State Management ---
let state = {
    currentPage: 1,
    pageSize: 20,
    statusInterval: null,
    lastStatus: { is_running: false, status: 'Unknown' },
    autoRefreshCounter: 0,
    autoRefreshInterval: 5, // Refresh every 5 status checks (10 seconds)
};

// --- Toast Notification System ---
function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'slideOut 0.5s forwards';
        toast.addEventListener('animationend', () => toast.remove());
    }, duration);
}

// --- DOMContentLoaded Listener ---
document.addEventListener('DOMContentLoaded', () => {
    switchTab('results');
    initializeDashboard();
    state.statusInterval = setInterval(fetchScanStatus, 2000);
});

function initializeDashboard() {
    fetchScanStatus();
    fetchStats();
    fetchResults(1);
    fetchHistory();
}

// --- Tab Management ---
function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    
    document.getElementById(`tab-${tabId}`).classList.add('active');
    document.querySelector(`.tab-btn[onclick="switchTab('${tabId}')"]`).classList.add('active');
}

// --- API Handling ---
async function handleApiResponse(response, successMessage) {
    if (response.ok) {
        if (successMessage) showToast(successMessage, 'success');
        // Handle cases with no JSON body
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
            return await response.json();
        }
        return {};
    } else {
        const errorData = await response.json().catch(() => ({ error: 'An unknown error occurred.' }));
        const errorMessage = errorData.error || `Request failed with status: ${response.status}`;
        showToast(errorMessage, 'error');
        console.error('API Error:', errorData);
        throw new Error(errorMessage);
    }
}

// --- Data Fetching & UI Updates ---
async function fetchStats() {
    try {
        const data = await handleApiResponse(await fetch(`${API_BASE}/stats`));
        document.getElementById('stat-total').textContent = data.total_open_records || 0;
        document.getElementById('stat-unique').textContent = data.unique_ips || 0;
        
        const portData = await handleApiResponse(await fetch(`${API_BASE}/stats/top-ports`));
        if (portData && portData.ports && portData.ports.length > 0) {
            document.getElementById('stat-top-port').textContent = `${portData.ports[0].port} (${portData.ports[0].open_count} times)`;
        } else {
            document.getElementById('stat-top-port').textContent = 'No data';
        }
    } catch (e) {
        console.error('Failed to fetch stats:', e);
    }
}

async function fetchScanStatus() {
    try {
        const data = await handleApiResponse(await fetch(`${API_BASE}/scan/status`));
        updateStatusUI(data);

        // Smartly refresh data based on status change
        if (data.is_running && !state.lastStatus.is_running) {
            showToast('Scan has started! Refreshing data.', 'info');
            fetchStats();
            fetchResults(1);
        } else if (!data.is_running && state.lastStatus.is_running) {
            showToast('Scan has stopped. Fetching final results.', 'info');
            fetchStats();
            fetchResults(1);
            fetchHistory();
        } else if (data.is_running) {
            // Auto-refresh results while running
            state.autoRefreshCounter++;
            if (state.autoRefreshCounter >= state.autoRefreshInterval) {
                fetchResults(state.currentPage);
                state.autoRefreshCounter = 0;
            }
        }
        
        state.lastStatus = data;

    } catch (e) {
        updateStatusUI({ status: 'Error', is_running: false });
        console.error('Failed to fetch scan status:', e);
    }
}

function updateStatusUI(data) {
    const statusEl = document.getElementById('scan-status');
    const roundEl = document.getElementById('scan-round');
    const scanIdEl = document.getElementById('scan-id');
    const startBtn = document.getElementById('btn-start');
    const stopBtn = document.getElementById('btn-stop');

    const statusText = data.status || (data.is_running ? 'Running' : 'Idle');
    statusEl.textContent = statusText;
    statusEl.className = `status-badge status-${statusText.toLowerCase()}`;
    
    roundEl.textContent = data.current_round || '-';
    scanIdEl.textContent = data.scan_id || '-';
    
    startBtn.disabled = data.is_running;
    stopBtn.disabled = !data.is_running;
}

// --- Actions ---
async function startScan() {
    if (!confirm('Are you sure you want to start a new scan?')) return;
    try {
        const response = await fetch(`${API_BASE}/scan/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}) // Default config
        });

        if (response.ok) {
            showToast('Scan started successfully!', 'success');
            fetchScanStatus();
        } else {
            const errorData = await response.json().catch(() => ({ error: 'An unknown error occurred.' }));
            
            // Check if error is "Scan is already running"
            if (errorData.code === 'SCAN_START_FAILED' && 
                errorData.error && 
                errorData.error.toLowerCase().includes('already running')) {
                // Silently update UI to reflect running state without showing error
                fetchScanStatus();
            } else {
                // Show error for other failures
                const errorMessage = errorData.error || `Request failed with status: ${response.status}`;
                showToast(errorMessage, 'error');
                console.error('API Error:', errorData);
            }
        }
    } catch (e) {
        console.error('Failed to start scan:', e);
    }
}

async function stopScan() {
    if (!confirm('Are you sure you want to stop the current scan?')) return;
    try {
        await handleApiResponse(
            await fetch(`${API_BASE}/scan/stop`, { method: 'POST' }),
            'Scan stop request sent.'
        );
        fetchScanStatus();
    } catch (e) {
        console.error('Failed to stop scan:', e);
    }
}

async function fetchResults(page) {
    state.currentPage = page;
    const tbody = document.querySelector('#results-table tbody');
    setTableLoading(tbody, 6);

    try {
        const data = await handleApiResponse(await fetch(`${API_BASE}/results?page=${page}&page_size=${state.pageSize}`));
        console.log('fetchResults received data:', data);
        console.log('fetchResults data.results:', data.results);
        renderTable(tbody, data.results, renderResultRow, 6, 'No results found.');
        updatePagination(data.page, data.total_pages);
    } catch (e) {
        setTableError(tbody, 6, 'Failed to load results.');
        console.error('Failed to fetch results:', e);
    }
}

async function fetchHistory() {
    const tbody = document.querySelector('#history-table tbody');
    setTableLoading(tbody, 5);

    try {
        const data = await handleApiResponse(await fetch(`${API_BASE}/scan/history`));
        renderTable(tbody, data.scans, renderHistoryRow, 5, 'No scan history found.');
    } catch (e) {
        setTableError(tbody, 5, 'Failed to load history.');
        console.error('Failed to fetch history:', e);
    }
}

// --- Table Rendering ---
function setTableLoading(tbody, colspan) {
    tbody.innerHTML = `<tr><td colspan="${colspan}" style="text-align:center">Loading...</td></tr>`;
}

function setTableError(tbody, colspan, message) {
    tbody.innerHTML = `<tr><td colspan="${colspan}" style="text-align:center; color: var(--danger-color);">${message}</td></tr>`;
}

function renderTable(tbody, items, rowRenderer, colspan, emptyMessage) {
    console.log('renderTable called with items:', items);
    tbody.innerHTML = '';
    if (items && Array.isArray(items) && items.length > 0) {
        items.forEach((item, index) => {
            console.log(`renderTable item ${index}:`, item);
            const tr = rowRenderer(item);
            tbody.appendChild(tr);
        });
    } else {
        tbody.innerHTML = `<tr><td colspan="${colspan}" style="text-align:center">${emptyMessage}</td></tr>`;
    }
}

function renderResultRow(item) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td>${item && item.ip_address ? item.ip_address : 'N/A'}</td>
        <td>${item && item.port ? item.port : 'N/A'}</td>
        <td>${item && item.ip_type ? item.ip_type : 'TCP'}</td>
        <td>${formatGeo(item)}</td>
        <td>${item && item.scan_round ? item.scan_round : 'N/A'}</td>
        <td>${item && item.first_seen ? new Date(item.first_seen).toLocaleString() : 'N/A'}</td>
    `;
    return tr;
}

function renderHistoryRow(item) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td>${item.round || '-'}</td>
        <td>${item.start_time ? new Date(item.start_time).toLocaleString() : '-'}</td>
        <td>${item.end_time ? new Date(item.end_time).toLocaleString() : '-'}</td>
        <td>${item.status || 'Completed'}</td>
        <td>${(item.total_open_ports || 0)} open ports, ${(item.ports_scanned || 0)} scanned</td>
    `;
    return tr;
}

// --- UI Helpers ---
function updatePagination(page, totalPages) {
    document.getElementById('page-info').textContent = `Page ${page} / ${totalPages}`;
    document.getElementById('prev-page').disabled = page <= 1;
    document.getElementById('next-page').disabled = page >= totalPages;
}

function formatGeo(item) {
    if (!item) return '-';
    const country = item.country || '';
    const city = item.city || '';
    if (!country && !city) return '-';
    return [country, city].filter(Boolean).join(', ');
}

function changePage(delta) {
    const newPage = state.currentPage + delta;
    if (newPage < 1) return;
    fetchResults(newPage);
}

function exportData(format) {
    showToast(`Preparing ${format.toUpperCase()} file for download...`, 'info');
    window.open(`${API_BASE}/export/${format}`, '_blank');
}
