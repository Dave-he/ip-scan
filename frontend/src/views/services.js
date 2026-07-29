// Services view: cards per detected service across all servers.

export class ServicesView {
    constructor(root) { this.root = root; }

    render(state) {
        const grid = this.root.querySelector('#services-grid');
        const services = state.services;
        if (!services.length) {
            grid.innerHTML = '<div class="muted" style="grid-column:1/-1;text-align:center;padding:40px">尚无服务数据 · 等待节点开启 --probe-service</div>';
            return;
        }
        grid.innerHTML = services.map((s) => {
            const top = s.open_ports;
            return `
            <div class="service-card">
                <div class="head">
                    <strong>${escapeHtml(s.service_name)}</strong>
                    <span class="meta">${s.unique_ips} IPs · ${top} ports</span>
                </div>
                <div class="muted" style="font-size:11px">${describeService(s.service_name)}</div>
            </div>`;
        }).join('');
    }
}

function describeService(name) {
    const known = {
        ssh: '远程 shell',
        http: 'Web (HTTP)',
        https: 'Web (HTTPS)',
        'http-alt': 'Web (备用端口)',
        'https-alt': 'Web (备用端口)',
        ftp: '文件传输 (明文)',
        telnet: '远程 shell (明文)',
        smtp: '邮件发送',
        pop3: '邮件接收',
        imap: '邮件接收',
        dns: '域名解析',
        mysql: 'MySQL 数据库',
        postgresql: 'PostgreSQL 数据库',
        mongodb: 'MongoDB 数据库',
        redis: 'Redis 缓存',
        elasticsearch: 'Elasticsearch 搜索',
        rdp: 'Windows 远程桌面',
        vnc: '虚拟网络控制台',
    };
    return known[name] || '—';
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
