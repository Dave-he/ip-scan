// Assets view: drillable list of distinct IPs with at least one open port.
// Uses the new /api/v1/assets endpoint that joins geo + service_info +
// top service + risk score in one round-trip. Click an IP -> IP-detail
// panel.

export class AssetsView {
    constructor(root) {
        this.root = root;
        this.search = '';
        this.filterService = '';
        this.filterCountry = '';
        this.minRisk = 0;
    }

    render(state) {
        const list = (state.assets || []).slice();
        const totalEl = document.getElementById('assets-count');
        if (totalEl) totalEl.textContent = `${list.length} 个独立资产`;

        // Build filter dropdowns from current data
        const allServices = new Set();
        const allCountries = new Set();
        for (const a of list) {
            if (a.top_service) allServices.add(a.top_service);
            if (a.country) allCountries.add(a.country);
        }

        const serviceSel = document.getElementById('assets-filter-service');
        if (serviceSel && serviceSel.options.length <= 1) {
            serviceSel.innerHTML = '<option value="">全部服务</option>' +
                Array.from(allServices).sort().map(s => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join('');
        }
        const countrySel = document.getElementById('assets-filter-country');
        if (countrySel && countrySel.options.length <= 1) {
            countrySel.innerHTML = '<option value="">全部国家</option>' +
                Array.from(allCountries).sort().map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
        }
        if (serviceSel) serviceSel.value = this.filterService;
        if (countrySel) countrySel.value = this.filterCountry;

        // Apply filters
        let rows = list;
        if (this.search) {
            const q = this.search.toLowerCase();
            rows = rows.filter(a => (a.ip || '').includes(q) || (a.reverse_dns || '').toLowerCase().includes(q) || (a.isp || '').toLowerCase().includes(q));
        }
        if (this.filterService) rows = rows.filter(a => a.top_service === this.filterService);
        if (this.filterCountry) rows = rows.filter(a => a.country === this.filterCountry);
        if (this.minRisk > 0) rows = rows.filter(a => (a.risk_score || 0) >= this.minRisk);

        const tb = this.root.querySelector('#tb-assets');
        if (!tb) return;
        if (!rows.length) {
            tb.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-dim);padding:30px">没有匹配的资产</td></tr>';
        } else {
            tb.innerHTML = rows.slice(0, 200).map(a => {
                const nodes = (a._servers || []).join(', ') || '—';
                const risk = a.risk_score || 0;
                const riskCls = risk >= 60 ? 'risk-high' : risk >= 30 ? 'risk-mid' : 'risk-low';
                return `<tr class="row-click" onclick="ui.ipDetailOpen('${escapeHtml(a.ip)}')">
                    <td>${escapeHtml(nodes)}</td>
                    <td style="font-family:var(--mono);color:var(--accent)">${escapeHtml(a.ip)}</td>
                    <td>${escapeHtml(a.country || '')} ${escapeHtml(a.city || '')}</td>
                    <td>${escapeHtml(a.isp || '')}</td>
                    <td>${escapeHtml(a.asn || '')}</td>
                    <td><span class="chip">${escapeHtml(a.top_service || '—')}</span> <span class="chip">${escapeHtml(a.category || '—')}</span></td>
                    <td style="font-family:var(--mono)">${a.open_ports}</td>
                    <td><span class="risk-pill ${riskCls}">${risk}</span></td>
                </tr>`;
            }).join('');
        }
    }

    setSearch(v) { this.search = v; }
    setService(v) { this.filterService = v; }
    setCountry(v) { this.filterCountry = v; }
    setMinRisk(v) { this.minRisk = v; }
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
