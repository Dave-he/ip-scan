// Scan control view: configure scan + show per-server scan status.

export class ScanView {
    constructor(root) { this.root = root; }

    render(state) {
        // Populate the node selector
        const sel = this.root.querySelector('#scan-target-node');
        const current = sel.value;
        sel.innerHTML = state.servers.length
            ? state.servers.map((s) => `<option value="${s.id}">${escapeHtml(s.label)} (${s.state})</option>`).join('')
            : '<option value="">无可用节点</option>';
        if (current && state.servers.some((s) => s.id === current)) sel.value = current;

        // Status list
        const list = this.root.querySelector('#scan-status-list');
        if (!state.servers.length) {
            list.innerHTML = '<div class="muted" style="padding:24px;text-align:center">尚无节点 · 请先在节点列表添加</div>';
            return;
        }
        list.innerHTML = state.servers.map((s) => {
            const st = s.cache.scanStatus || {};
            const running = st.is_running;
            const cls = running ? 'running' : (s.state === 'online' ? 'idle' : 'offline');
            const label = running ? 'RUNNING' : (st.db_status || (s.state === 'online' ? 'IDLE' : 'OFFLINE'));
            const target = st.current_target_start && st.current_target_end
                ? `${st.current_target_start} → ${st.current_target_end}`
                : (s.system?.current_target_start ? `${s.system.current_target_start} → ${s.system.current_target_end}` : '—');
            return `
            <div class="server-detail-card">
                <div class="head">
                    <span class="label">
                        <span class="pill ${s.state}"></span>
                        ${escapeHtml(s.label)}
                    </span>
                    <span class="pill ${cls}">${escapeHtml(label)}</span>
                </div>
                <div class="url">${escapeHtml(s.url)}</div>
                <div class="muted" style="font-size:11px">目标: <span style="font-family:var(--mono);color:var(--text)">${escapeHtml(target)}</span></div>
                ${st.last_scan_time ? `<div class="muted" style="font-size:11px">最近扫描: ${escapeHtml(st.last_scan_time)}</div>` : ''}
                ${running ? `<button class="text-btn" style="margin-top:6px;color:var(--danger)" onclick="ui.scanStopFor('${s.id}')">⏹ 停止</button>` : ''}
            </div>`;
        }).join('');
    }
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
