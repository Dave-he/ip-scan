// Results view: aggregated results table with search + filters + pagination.
// Each row links to the IP-detail panel for full drill-down.

export class ResultsView {
    constructor(root) {
        this.root = root;
        this.page = 1;
        this.pageSize = 50;
        this.search = '';
        this.filterService = '';
    }

    render(state) {
        const all = state.results;
        document.getElementById('result-count').textContent = `${all.length} 条去重记录`;

        // Build service filter chips from current snapshot
        const svcSel = document.getElementById('results-filter-service');
        if (svcSel && svcSel.options.length <= 1) {
            const set = new Set();
            for (const r of all) if (r.service_name) set.add(r.service_name);
            svcSel.innerHTML = '<option value="">全部服务</option>' +
                Array.from(set).sort().map(s => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join('');
        }
        if (svcSel) svcSel.value = this.filterService;

        let rows = all;
        if (this.search) {
            const q = this.search.toLowerCase();
            rows = rows.filter(r => (r.ip_address || '').includes(q)
                || String(r.port).includes(q)
                || (r.country || '').toLowerCase().includes(q)
                || (r.city || '').toLowerCase().includes(q)
                || (r.isp || '').toLowerCase().includes(q)
                || (r.asn || '').toLowerCase().includes(q)
                || (r.reverse_dns || '').toLowerCase().includes(q));
        }
        if (this.filterService) rows = rows.filter(r => r.service_name === this.filterService);

        const totalPages = Math.max(1, Math.ceil(rows.length / this.pageSize));
        if (this.page > totalPages) this.page = totalPages;
        const slice = rows.slice((this.page - 1) * this.pageSize, this.page * this.pageSize);

        document.getElementById('result-tab-count').textContent = rows.length;

        const tb = this.root.querySelector('#tb-results');
        if (!slice.length) {
            tb.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-dim);padding:30px">没有匹配结果</td></tr>';
        } else {
            tb.innerHTML = slice.map(r => {
                const nodes = (r._servers || []).join(', ') || '—';
                const risk = r.risk_score || 0;
                const riskCls = risk >= 60 ? 'risk-high' : risk >= 30 ? 'risk-mid' : 'risk-low';
                return `<tr class="row-click" onclick="ui.ipDetailOpen('${escapeHtml(r.ip_address)}')">
                    <td>${escapeHtml(nodes)}</td>
                    <td style="font-family:var(--mono);color:var(--accent)">${escapeHtml(r.ip_address)}</td>
                    <td>${escapeHtml(r.ip_type || '')}</td>
                    <td style="font-family:var(--mono)">${r.port}</td>
                    <td><span class="chip">${escapeHtml(r.service_name || guessService(r.port))}</span></td>
                    <td>${escapeHtml((r.country || '') + (r.city ? ' · ' + r.city : ''))}</td>
                    <td>${escapeHtml((r.isp || '—') + (r.asn ? ' · ' + r.asn : ''))}</td>
                    <td style="color:var(--text-dim);font-size:11px">${escapeHtml(r.banner ? truncate(r.banner, 60) : '')}</td>
                    <td><span class="risk-pill ${riskCls}">${risk}</span></td>
                </tr>`;
            }).join('');
        }

        document.getElementById('pg-info').textContent = `${this.page} / ${totalPages} (${rows.length} 条)`;
        document.getElementById('pg-prev').disabled = this.page <= 1;
        document.getElementById('pg-next').disabled = this.page >= totalPages;
    }

    setSearch(value) {
        this.search = value;
        this.page = 1;
    }
    setService(value) {
        this.filterService = value;
        this.page = 1;
    }
    pageStep(d) {
        this.page = Math.max(1, this.page + d);
    }
}

function guessService(port) {
    const known = { 22: 'ssh', 80: 'http', 443: 'https', 21: 'ftp', 23: 'telnet', 25: 'smtp', 53: 'dns', 3306: 'mysql', 5432: 'postgresql', 6379: 'redis', 3389: 'rdp', 8080: 'http-alt', 8443: 'https-alt' };
    return known[port] || '—';
}

function truncate(s, n) {
    if (!s) return '';
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
