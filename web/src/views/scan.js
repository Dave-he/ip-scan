// Scan control view: configure scan + show per-server scan status.
// Adds preset selector (quick / web / db / ssh / full) and per-target
// sliders for timeout / concurrency. Status panel mirrors ScanStatus.

const PRESETS = [
    { id: 'quick', label: '快速 (Top 100 端口)', target: '127.0.0.0/24', ports: '21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017' },
    { id: 'web', label: 'Web 服务', target: '127.0.0.0/24', ports: '80,443,8080,8443,8000,8888,3000,5000,9000' },
    { id: 'db', label: '数据库', target: '127.0.0.0/24', ports: '1433,1521,3306,5432,6379,9200,11211,27017,8529' },
    { id: 'ssh', label: 'SSH / RDP / 远程', target: '127.0.0.0/24', ports: '22,23,53,3389,5900,2222,8022' },
    { id: 'mail', label: '邮件', target: '127.0.0.0/24', ports: '25,110,143,465,587,993,995' },
    { id: 'full', label: '全端口 (1-65535)', target: '127.0.0.0/24', ports: '1-65535' },
];

export class ScanView {
    constructor(root) { this.root = root; }

    render(state) {
        const sel = this.root.querySelector('#scan-target-node');
        const current = sel.value;
        sel.innerHTML = state.servers.length
            ? state.servers.map((s) => `<option value="${s.id}">${escapeHtml(s.label)} (${s.state})</option>`).join('')
            : '<option value="">无可用节点</option>';
        if (current && state.servers.some((s) => s.id === current)) sel.value = current;

        // Preset selector — fills target/ports and is one click away.
        const presetSel = this.root.querySelector('#scan-preset');
        if (presetSel && presetSel.options.length <= 1) {
            presetSel.innerHTML = '<option value="">— 选择预设 —</option>' +
                PRESETS.map(p => `<option value="${p.id}">${escapeHtml(p.label)}</option>`).join('');
        }

        const list = this.root.querySelector('#scan-status-list');
        if (!state.servers.length) {
            list.innerHTML = '<div class="muted" style="padding:24px;text-align:center">尚无节点 · 请先在节点列表添加</div>';
            return;
        }
        list.innerHTML = state.servers.map((s) => {
            const st = s.cache.scanStatus || {};
            const running = !!st.is_running;
            const online = s.state === 'online';
            const cls = running ? 'running' : (online ? 'idle' : 'offline');
            const label = running ? 'RUNNING' : (online ? 'IDLE' : 'OFFLINE');
            const target = running && st.current_target_start && st.current_target_end
                ? `${st.current_target_start} → ${st.current_target_end}`
                : '—';
            const runningSince = running && st.start_time
                ? `<div class="muted" style="font-size:11px">开始于: ${escapeHtml(st.start_time)}</div>`
                : '';
            return `
            <div class="server-detail-card">
                <div class="head">
                    <span class="label">
                        <span class="pill ${online ? 'online' : cls}"></span>
                        ${escapeHtml(s.label)}
                    </span>
                    <span class="pill ${cls}">${escapeHtml(label)}</span>
                </div>
                <div class="url">${escapeHtml(s.url)}</div>
                <div class="muted" style="font-size:11px">当前目标: <span style="font-family:var(--mono);color:var(--text)">${escapeHtml(target)}</span></div>
                ${st.last_scan_time ? `<div class="muted" style="font-size:11px">最近扫描: ${escapeHtml(st.last_scan_time)}</div>` : ''}
                ${runningSince}
                ${running ? `<button class="text-btn" style="margin-top:6px;color:var(--danger)" onclick="ui.scanStopFor('${s.id}')">⏹ 停止</button>` : ''}
            </div>`;
        }).join('');
    }

    applyPreset(id) {
        const p = PRESETS.find(x => x.id === id);
        if (!p) return;
        document.getElementById('scan-target').value = p.target;
        document.getElementById('scan-ports').value = p.ports;
    }
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
