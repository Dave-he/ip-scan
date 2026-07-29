// IP-detail view: a slide-out panel that appears when the operator clicks
// an IP in any view (map, results, assets). Shows everything the backend
// knows about a single IP: geo, ASN, risk, services, banners, TLS.

export class IpDetailView {
    constructor(root) {
        this.root = root;
        this.current = null;
        this.loading = false;
        this.snapshots = null;
        this.closeHandler = null;
    }

    attachCloseHandler(fn) { this.closeHandler = fn; }

    async show(ip, client) {
        if (!ip) return;
        this.current = ip;
        this.loading = true;
        this._renderShell();
        if (!client) {
            this._renderError('未选择后端节点');
            return;
        }
        try {
            const [detail, snaps] = await Promise.all([
                client.getIpDetail(ip),
                client.getSnapshots(ip).catch(() => ({ snapshots: [] })),
            ]);
            this._renderDetail(detail);
            this.snapshots = snaps.snapshots || [];
            this._renderSnapshots();
        } catch (e) {
            this._renderError(e.message || '查询失败');
        } finally {
            this.loading = false;
        }
    }

    hide() {
        this.current = null;
        this._renderShell();
    }

    _renderShell() {
        if (!this.current) {
            this.root.innerHTML = '';
            this.root.style.display = 'none';
            return;
        }
        this.root.style.display = 'flex';
        if (this.loading) {
            this.root.innerHTML = `
                <div class="ipd-shell">
                    <div class="ipd-head">
                        <strong>${escapeHtml(this.current)}</strong>
                        <button class="text-btn" onclick="ui.ipDetailClose()">关闭 ×</button>
                    </div>
                    <div class="ipd-body"><div class="muted" style="padding:30px">查询中…</div></div>
                </div>`;
        }
    }

    _renderError(msg) {
        this.root.innerHTML = `
            <div class="ipd-shell">
                <div class="ipd-head">
                    <strong>${escapeHtml(this.current || '')}</strong>
                    <button class="text-btn" onclick="ui.ipDetailClose()">关闭 ×</button>
                </div>
                <div class="ipd-body"><div class="muted" style="padding:30px;color:var(--danger)">${escapeHtml(msg)}</div></div>
            </div>`;
    }

    _renderDetail(d) {
        const ports = d.open_ports || [];
        const reasons = (d.risk_reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join('');
        const peerBits = [];
        if (d.asn && d.asn_peer_count != null) peerBits.push(`<span class="chip">ASN ${escapeHtml(d.asn)} · ${d.asn_peer_count} 个 IP</span>`);
        if (d.isp && d.isp_peer_count != null) peerBits.push(`<span class="chip">${escapeHtml(d.isp)} · ${d.isp_peer_count} 个 IP</span>`);
        const peerRow = peerBits.length ? `<div class="ipd-peer">${peerBits.join(' ')}</div>` : '';

        const html = `
            <div class="ipd-shell">
                <div class="ipd-head">
                    <div>
                        <strong style="font-family:var(--mono);font-size:16px">${escapeHtml(d.ip)}</strong>
                        <span class="chip">${escapeHtml(d.ip_type || '')}</span>
                        <span class="chip risk" data-risk="${d.risk_score}">风险 ${d.risk_score}</span>
                        <span class="chip">${escapeHtml(d.category || 'unknown')}</span>
                    </div>
                    <div style="display:flex;gap:6px">
                        <button class="text-btn" onclick="ui.copyText('${escapeHtml(d.ip)}')">复制 IP</button>
                        <button class="text-btn" onclick="ui.ipDetailClose()">关闭 ×</button>
                    </div>
                </div>
                <div class="ipd-meta">
                    <div><span class="muted">国家 / 地区</span><strong>${escapeHtml(d.country || '—')} ${escapeHtml(d.region || '')}</strong></div>
                    <div><span class="muted">城市</span><strong>${escapeHtml(d.city || '—')}</strong></div>
                    <div><span class="muted">ASN</span><strong>${escapeHtml(d.asn || '—')}</strong></div>
                    <div><span class="muted">运营商</span><strong>${escapeHtml(d.isp || '—')}</strong></div>
                    <div><span class="muted">反向 DNS</span><strong>${escapeHtml(d.reverse_dns || '—')}</strong></div>
                    <div><span class="muted">首/末次</span><strong>${escapeHtml(d.first_seen || '—')} → ${escapeHtml(d.last_seen || '—')}</strong></div>
                </div>
                ${peerRow}
                ${reasons ? `<div class="ipd-risk"><strong>风险原因</strong><ul>${reasons}</ul></div>` : ''}
                <div class="ipd-section">
                    <div class="ipd-section-title">开放端口 (${ports.length})</div>
                    <table class="ipd-ports">
                        <thead><tr><th>端口</th><th>服务</th><th>Banner / Title</th><th>首/末次</th></tr></thead>
                        <tbody>${ports.map(p => `
                            <tr>
                                <td style="font-family:var(--mono)">${p.port}</td>
                                <td>${escapeHtml(p.service_name || '—')}</td>
                                <td title="${escapeHtml(p.banner || '')}">${escapeHtml(truncate(p.banner || '—', 80))}</td>
                                <td class="muted" style="font-size:11px">${escapeHtml(p.first_seen || '')} → ${escapeHtml(p.last_seen || '')}</td>
                            </tr>
                        `).join('') || '<tr><td colspan="4" class="muted" style="padding:12px">无开放端口</td></tr>'}</tbody>
                    </table>
                </div>
                <div class="ipd-section">
                    <div class="ipd-section-title">TCP 抓包快照 (${this.snapshots ? this.snapshots.length : 0})</div>
                    <div id="ipd-snapshots"></div>
                </div>
            </div>
        `;
        this.root.innerHTML = html;
    }

    _renderSnapshots() {
        const target = document.getElementById('ipd-snapshots');
        if (!target) return;
        if (!this.snapshots || !this.snapshots.length) {
            target.innerHTML = '<div class="muted" style="padding:12px">尚无快照数据 · 服务探测 (--probe-service) 写入 tcp_snapshots 后才会出现</div>';
            return;
        }
        target.innerHTML = this.snapshots.map(s => `
            <div class="ipd-snap">
                <div class="ipd-snap-head">
                    <span class="chip">${escapeHtml(s.protocol || 'tcp')}</span>
                    <strong style="font-family:var(--mono)">${s.port}</strong>
                    ${s.purpose ? `<span class="muted">${escapeHtml(s.purpose)}</span>` : ''}
                    ${s.http_status ? `<span class="chip">HTTP ${s.http_status}</span>` : ''}
                    ${s.tls_version ? `<span class="chip">${escapeHtml(s.tls_version)}</span>` : ''}
                    ${s.os_guess ? `<span class="chip">${escapeHtml(s.os_guess)}</span>` : ''}
                </div>
                ${s.http_title ? `<div class="ipd-line"><span class="muted">Title:</span> ${escapeHtml(s.http_title)}</div>` : ''}
                ${s.http_server ? `<div class="ipd-line"><span class="muted">Server:</span> ${escapeHtml(s.http_server)}</div>` : ''}
                ${s.tls_subject ? `<div class="ipd-line"><span class="muted">TLS Subject:</span> ${escapeHtml(s.tls_subject)}</div>` : ''}
                ${s.tls_issuer ? `<div class="ipd-line"><span class="muted">Issuer:</span> ${escapeHtml(s.tls_issuer)}</div>` : ''}
                ${s.tls_not_before || s.tls_not_after ? `<div class="ipd-line"><span class="muted">有效期:</span> ${escapeHtml(s.tls_not_before || '')} → ${escapeHtml(s.tls_not_after || '')}</div>` : ''}
                ${s.banner_first_line ? `<div class="ipd-line"><span class="muted">Banner:</span> <code>${escapeHtml(truncate(s.banner_first_line, 200))}</code></div>` : ''}
                ${s.banner_raw_hex ? `<details><summary class="muted">Raw bytes (${s.banner_raw_len} B)</summary><pre class="ipd-hex">${escapeHtml(s.banner_raw_hex)}</pre></details>` : ''}
                ${s.detected_technologies ? `<div class="ipd-line"><span class="muted">Technologies:</span> ${escapeHtml(s.detected_technologies)}</div>` : ''}
            </div>
        `).join('');
    }
}

function truncate(s, n) {
    if (!s) return '';
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
}
function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
