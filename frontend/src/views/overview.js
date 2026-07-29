// Overview view: cluster-wide metrics, heatmap of node contributions, top services.

export class OverviewView {
    constructor(root) { this.root = root; }

    render(state) {
        const { servers, totals, services } = state;
        const onlineNodes = servers.filter((s) => s.state === 'online').length;
        const totalNodes = servers.length;

        this.root.querySelector('#m-ports').textContent = totals.ports.toLocaleString();
        // For unique IPs we approximate by deduplicated (ip, port) records × ip set;
        // for now show "total open records across all servers" if no per-server cache:
        const uniqueIps = new Set(state.results.map((r) => r.ip_address)).size;
        this.root.querySelector('#m-ips').textContent = uniqueIps.toLocaleString();
        this.root.querySelector('#m-nodes').textContent = `${onlineNodes}/${totalNodes}`;

        const top = state._topPort;
        this.root.querySelector('#m-topport').textContent = top ? top.port : '—';

        // Sidebar cluster summary
        document.getElementById('cs-nodes').textContent = totalNodes;
        document.getElementById('cs-ips').textContent = uniqueIps.toLocaleString();
        document.getElementById('cs-ports').textContent = totals.ports.toLocaleString();

        // Heatmap
        const heatmap = this.root.querySelector('#node-heatmap');
        if (!servers.length) {
            heatmap.innerHTML = '<div class="muted" style="grid-column:1/-1;text-align:center;padding:40px">尚无节点 · 点击 + 服务器 添加</div>';
        } else {
            heatmap.innerHTML = servers.map((s) => {
                const stats = s.cache.stats || {};
                const portCount = stats.total_open_records || 0;
                const ips = stats.unique_ips || 0;
                return `
                <div class="node-heat-card" onclick="ui.focusServer('${s.id}')">
                    <div class="label">
                        <span class="pill ${s.state}"></span>
                        ${escapeHtml(s.label)}
                    </div>
                    <div class="url">${escapeHtml(s.url)}</div>
                    <div class="count">${portCount.toLocaleString()}</div>
                    <div class="sub">${ips.toLocaleString()} 个独立 IP · ${portCount} 条记录</div>
                </div>`;
            }).join('');
        }

        // Service bar
        this._renderServiceBar(services);
    }

    _renderServiceBar(services) {
        const bar = this.root.querySelector('#port-bar');
        const legend = this.root.querySelector('#port-legend');
        if (!services.length) {
            bar.innerHTML = '<div class="muted" style="padding:30px;text-align:center">暂无服务数据</div>';
            legend.innerHTML = '';
            return;
        }
        const top = services.slice(0, 8);
        const max = Math.max(...top.map((s) => s.unique_ips));
        bar.innerHTML = top.map((s) => {
            const w = (s.unique_ips / max) * 100;
            return `
            <div class="port-bar-row">
                <span class="label">${escapeHtml(s.service_name)}</span>
                <div class="bar"><span style="width:${w.toFixed(1)}%"></span></div>
                <span class="value">${s.unique_ips.toLocaleString()} IPs</span>
            </div>`;
        }).join('');
        legend.innerHTML = services.slice(0, 12).map((s) => {
            return `<span class="chip">${escapeHtml(s.service_name)} · ${s.unique_ips}</span>`;
        }).join('');
    }
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
