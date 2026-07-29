// Family view: IPv4 vs IPv6 split + category donut + ASN / Org breakdown.

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
                label: '资产分类',
                ips: state.categories.reduce((a, c) => a + c.unique_ips, 0),
                ports: state.categories.length,
                desc: '按服务类别拆分',
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

        // ASN bar
        const asnBar = this.root.querySelector('#asn-bar');
        const asns = state.asns || [];
        if (asnBar) {
            if (!asns.length) {
                asnBar.innerHTML = '<div class="muted" style="padding:30px;text-align:center">尚无 ASN 数据 · 等待 GeoService 写入 ip_details</div>';
            } else {
                const top = asns.slice(0, 8);
                const max = Math.max(...top.map(a => a.unique_ips));
                asnBar.innerHTML = top.map(a => {
                    const w = (a.unique_ips / max) * 100;
                    return `<div class="port-bar-row">
                        <span class="label" title="${escapeHtml(a.asn)}">${escapeHtml(a.asn)}</span>
                        <div class="bar"><span style="width:${w.toFixed(1)}%"></span></div>
                        <span class="value">${a.unique_ips.toLocaleString()} IPs · ${a.open_ports.toLocaleString()} ports</span>
                    </div>`;
                }).join('');
            }
        }

        // Org bar
        const orgBar = this.root.querySelector('#org-bar');
        const orgs = state.organizations || [];
        if (orgBar) {
            if (!orgs.length) {
                orgBar.innerHTML = '<div class="muted" style="padding:30px;text-align:center">尚无运营商数据 · 等待 GeoService 写入 ip_details</div>';
            } else {
                const top = orgs.slice(0, 8);
                const max = Math.max(...top.map(o => o.unique_ips));
                orgBar.innerHTML = top.map(o => {
                    const w = (o.unique_ips / max) * 100;
                    return `<div class="port-bar-row">
                        <span class="label" title="${escapeHtml(o.isp)}">${escapeHtml(o.isp)}</span>
                        <div class="bar"><span style="width:${w.toFixed(1)}%"></span></div>
                        <span class="value">${o.unique_ips.toLocaleString()} IPs · ${o.open_ports.toLocaleString()} ports</span>
                    </div>`;
                }).join('');
            }
        }
    }
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
