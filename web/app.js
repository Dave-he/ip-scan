const API_BASE = '/api/v1';

let currentPage = 1;
const pageSize = 20;
let statusInterval = null;
let lastStatus = { is_running: false };

// --- Toast Notification System ---
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'slideOut 0.5s forwards';
        toast.addEventListener('animationend', () => toast.remove());
    }, 4000);
}

document.addEventListener('DOMContentLoaded', () => {
    switchTab('results');
    fetchInitialData();
    
    statusInterval = setInterval(fetchScanStatus, 2000);
});

function fetchInitialData() {
    fetchScanStatus();
    fetchStats();
    fetchResults(1);
    fetchHistory();
}

function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    
    document.getElementById(`tab-${tabId}`).classList.add('active');
    document.querySelector(`.tab-btn[onclick="switchTab('${tabId}')"]`).classList.add('active');
}

async function handleApiResponse(response, successMessage) {
    if (response.ok) {
        if (successMessage) showToast(successMessage, 'success');
        return await response.json();
    } else {
        const errorData = await response.json();
        const errorMessage = errorData.error || `请求失败，状态码: ${response.status}`;
        showToast(errorMessage, 'error');
        console.error('API Error:', errorData);
        throw new Error(errorMessage);
    }
}

async function fetchStats() {
    try {
        const data = await handleApiResponse(await fetch(`${API_BASE}/stats`));
        document.getElementById('stat-total').textContent = data.total_open_records || 0;
        document.getElementById('stat-unique').textContent = data.unique_ips || 0;
        
        const portRes = await fetch(`${API_BASE}/stats/top-ports`);
        const portData = await handleApiResponse(portRes);
        if (portData && portData.ports && portData.ports.length > 0) {
            document.getElementById('stat-top-port').textContent = `${portData.ports[0].port} (${portData.ports[0].open_count}次)`;
        } else {
            document.getElementById('stat-top-port').textContent = '暂无数据';
        }
    } catch (e) {
        console.error('获取统计数据失败:', e);
    }
}

async function fetchScanStatus() {
    try {
        const data = await handleApiResponse(await fetch(`${API_BASE}/scan/status`));
        updateStatusUI(data);

        // If status changed, refresh data
        if (data.is_running !== lastStatus.is_running) {
            fetchStats();
            fetchResults(1);
        }
        lastStatus = data;

    } catch (e) {
        updateStatusUI({ status: 'Error', is_running: false });
        console.error('获取扫描状态失败:', e);
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

async function startScan() {
    if (!confirm('确定要开始新的扫描吗？')) return;
    try {
        await handleApiResponse(
            await fetch(`${API_BASE}/scan/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}) // Default config
            }),
            '扫描已成功启动！'
        );
        fetchScanStatus();
    } catch (e) {
        console.error('启动扫描失败:', e);
    }
}

async function stopScan() {
    if (!confirm('确定要停止当前扫描吗？')) return;
    try {
        await handleApiResponse(
            await fetch(`${API_BASE}/scan/stop`, { method: 'POST' }),
            '扫描停止请求已发送。'
        );
        fetchScanStatus();
    } catch (e) {
        console.error('停止扫描失败:', e);
    }
}

async function fetchResults(page) {
    currentPage = page;
    const tbody = document.querySelector('#results-table tbody');
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center">正在加载...</td></tr>';

    try {
        const data = await handleApiResponse(await fetch(`${API_BASE}/results?page=${page}&page_size=${pageSize}`));
        
        tbody.innerHTML = ''; // Clear loading state
        if (data.results && data.results.length > 0) {
            data.results.forEach(item => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${item.ip_address}</td>
                    <td>${item.port}</td>
                    <td>${item.ip_type || 'TCP'}</td>
                    <td>${formatGeo(item)}</td>
                    <td>${item.scan_round}</td>
                    <td>${new Date(item.first_seen).toLocaleString()}</td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center">未找到任何结果。</td></tr>';
        }
        
        updatePagination(data.page, data.total_pages);
        
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--danger-color);">加载结果失败。</td></tr>';
        console.error('获取扫描结果失败:', e);
    }
}

function updatePagination(page, totalPages) {
    document.getElementById('page-info').textContent = `第 ${page} / ${totalPages} 页`;
    document.getElementById('prev-page').disabled = page <= 1;
    document.getElementById('next-page').disabled = page >= totalPages;
}

function formatGeo(item) {
    if (!item.country && !item.city) return '-';
    let parts = [item.country, item.city].filter(Boolean);
    return parts.join(', ');
}

function changePage(delta) {
    const newPage = currentPage + delta;
    if (newPage < 1) return;
    fetchResults(newPage);
}

async function fetchHistory() {
    const tbody = document.querySelector('#history-table tbody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center">正在加载...</td></tr>';

    try {
        const data = await handleApiResponse(await fetch(`${API_BASE}/scan/history`));
        
        tbody.innerHTML = '';
        if (data.scans && Array.isArray(data.scans) && data.scans.length > 0) {
            data.scans.forEach(item => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${item.round || '-'}</td>
                    <td>${item.start_time ? new Date(item.start_time).toLocaleString() : '-'}</td>
                    <td>${item.end_time ? new Date(item.end_time).toLocaleString() : '-'}</td>
                    <td>${item.status || '已完成'}</td>
                    <td>${item.total_open_ports || 0} 开放端口, ${item.ports_scanned || 0} 已扫描</td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center">未找到任何扫描历史。</td></tr>';
        }
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--danger-color);">加载历史失败。</td></tr>';
        console.error('获取扫描历史失败:', e);
    }
}

function exportData(format) {
    showToast(`正在准备 ${format.toUpperCase()} 文件下载...`, 'info');
    window.open(`${API_BASE}/export/${format}`, '_blank');
}
