// IP family view: IPv4 vs IPv6 split.

export class FamilyView {
    constructor(root) { this.root = root; }

    render(state) {
        const grid = this.root.querySelector('#family-grid');
        const fam = state.families;
        const cards = [
            {
                label: 'IPv4',
                ips: fam.ipv4_unique_ips,
                ports: fam.ipv4_open_ports,
                desc: '传统 32 位 IP',
            },
            {
                label: 'IPv6',
                ips: fam.ipv6_unique_ips,
                ports: fam.ipv6_open_ports,
                desc: '128 位下一代 IP',
            },
            {
                label: 'Categories',
                ips: state.categories.reduce((a, c) => a + c.unique_ips, 0),
                ports: state.categories.length,
                desc: '资产分类汇总',
                list: state.categories.slice(0, 6),
            },
        ];
        grid.innerHTML = cards.map((c) => {
            const list = c.list ? `
                <div style="margin-top:10px;text-align:left">
                    ${c.list.map((x) => `<div style="display:flex;justify-content:space-between;font-size:11px;padding:2px 0"><span class="muted">${escapeHtml(x.category)}</span><span style="font-family:var(--mono);color:var(--accent)">${x.unique_ips}</span></div>`).join('')}
                </div>` : '';
            return `
            <div class="family-card">
                <div class="label">${c.label}</div>
                <div class="big">${(c.ips || 0).toLocaleString()}</div>
                <div class="muted" style="font-size:11px">${c.desc}</div>
                <div class="breakdown">
                    <div><strong>${(c.ips || 0).toLocaleString()}</strong>独立 IP</div>
                    <div><strong>${(c.ports || 0).toLocaleString()}</strong>开放端口</div>
                </div>
                ${list}
            </div>`;
        }).join('');
    }
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
