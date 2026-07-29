// Servers view: per-server detail cards.

export class ServersView {
    constructor(root) { this.root = root; }

    render(state) {
        const grid = this.root.querySelector('#server-detail-list');
        const servers = state.servers;
        if (!servers.length) {
            grid.innerHTML = '<div class="muted" style="grid-column:1/-1;text-align:center;padding:40px">尚无节点 · 点击 + 添加节点</div>';
            return;
        }
        grid.innerHTML = servers.map((s) => {
            const sys = s.system || {};
            const stats = s.cache.stats || {};
            const ports = stats.total_open_records || 0;
            const ips = stats.unique_ips || 0;
            const target = sys.current_target_start && sys.current_target_end
                ? `${sys.current_target_start} → ${sys.current_target_end}`
                : '—';
            const services = s.cache.byService;
            const topService = services && services.services && services.services[0];
            return `
            <div class="server-detail-card">
                <div class="head">
                    <span class="label">
                        <span class="pill ${s.state}"></span>
                        ${escapeHtml(s.label)}
                    </span>
                    <span class="pill ${s.state}">${s.state.toUpperCase()}</span>
                </div>
                <div class="url">${escapeHtml(s.url)}</div>
                <div class="muted" style="font-size:11px">
                    ${s.provider ? escapeHtml(s.provider) + ' · ' : ''}
                    ${s.latitude != null ? `${s.latitude.toFixed(4)}, ${s.longitude.toFixed(4)}` : ''}
                </div>
                <div class="muted" style="font-size:11px">当前目标: <span style="font-family:var(--mono);color:var(--text)">${escapeHtml(target)}</span></div>
                <div class="grid-2x">
                    <div><strong>${ports.toLocaleString()}</strong><small>开放端口记录</small></div>
                    <div><strong>${ips.toLocaleString()}</strong><small>独立 IP</small></div>
                    <div><strong>${stats.current_round || 1}</strong><small>扫描轮次</small></div>
                    <div><strong>${topService ? escapeHtml(topService.service_name) : '—'}</strong><small>最常见服务</small></div>
                </div>
                ${s.lastError ? `<div class="muted" style="color:var(--danger);font-size:11px">${escapeHtml(s.lastError)}</div>` : ''}
            </div>`;
        }).join('');
    }
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
