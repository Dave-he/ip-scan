// Results view: aggregated results table with search + pagination.

export class ResultsView {
    constructor(root) {
        this.root = root;
        this.page = 1;
        this.pageSize = 50;
        this.search = '';
    }

    render(state) {
        // The aggregated state.results is already deduped across servers.
        // For pagination we filter client-side (results list fits in memory).
        const all = state.results;
        document.getElementById('result-count').textContent = `${all.length} 条去重记录`;

        let rows = all;
        if (this.search) {
            const s = this.search.toLowerCase();
            rows = rows.filter((r) => (r.ip_address || '').includes(s) || String(r.port).includes(s) || (r.country || '').toLowerCase().includes(s) || (r.city || '').toLowerCase().includes(s));
        }
        const totalPages = Math.max(1, Math.ceil(rows.length / this.pageSize));
        if (this.page > totalPages) this.page = totalPages;
        const slice = rows.slice((this.page - 1) * this.pageSize, this.page * this.pageSize);

        document.getElementById('result-tab-count').textContent = rows.length;

        const tb = this.root.querySelector('#tb-results');
        if (!slice.length) {
            tb.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#5d6786;padding:30px">没有匹配结果</td></tr>';
        } else {
            tb.innerHTML = slice.map((r) => {
                const nodes = (r._servers || []).join(', ') || '—';
                return `<tr>
                    <td>${escapeHtml(nodes)}</td>
                    <td style="font-family:var(--mono);color:var(--accent)">${escapeHtml(r.ip_address)}</td>
                    <td>${escapeHtml(r.ip_type || '')}</td>
                    <td style="font-family:var(--mono)">${r.port}</td>
                    <td>${escapeHtml(guessService(r.port))}</td>
                    <td>${escapeHtml((r.country || '') + (r.city ? ' · ' + r.city : ''))}</td>
                    <td style="color:var(--text-dim);font-size:11px">${escapeHtml(r.first_seen || '')}</td>
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

    pageStep(d) {
        this.page = Math.max(1, this.page + d);
    }
}

function guessService(port) {
    const known = { 22: 'ssh', 80: 'http', 443: 'https', 21: 'ftp', 23: 'telnet', 25: 'smtp', 53: 'dns', 3306: 'mysql', 5432: 'postgresql', 6379: 'redis', 3389: 'rdp', 8080: 'http-alt', 8443: 'https-alt' };
    return known[port] || '—';
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
