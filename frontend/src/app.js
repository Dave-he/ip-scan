// Main entrypoint for the IP-Scan distributed frontend.
// Wires the connection manager, aggregator, views, and UI shell together.

import { BackendClient } from './api.js';
import { Aggregator } from './aggregator.js';
import { OverviewView } from './views/overview.js';
import { MapView } from './views/map.js';
import { ServicesView } from './views/services.js';
import { FamilyView } from './views/family.js';
import { ServersView } from './views/servers.js';
import { ResultsView } from './views/results.js';
import { ScanView } from './views/scan.js';

const STORAGE_KEY = 'ipscan-distributed-servers-v1';
const REFRESH_INTERVAL_MS = 8000;

class App {
    constructor() {
        this.aggregator = new Aggregator();
        this.servers = []; // [{ id, label, url, provider, latitude, longitude }]
        this.views = {
            overview: new OverviewView(document),
            map: new MapView(document),
            services: new ServicesView(document),
            family: new FamilyView(document),
            servers: new ServersView(document),
            results: new ResultsView(document),
            scan: new ScanView(document),
        };
        this.currentView = 'overview';
        this.refreshTimer = null;
        this.lastSnapshot = null;
    }

    async init() {
        this._loadServers();
        this._wireUi();
        await this._connectAll();
        this._notifyViews();
        this._startRefreshLoop();
        window.app = this;
        window.ui = ui; // UI helper is defined below
    }

    _loadServers() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            this.servers = raw ? JSON.parse(raw) : [];
        } catch (e) {
            this.servers = [];
        }
    }

    _saveServers() {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(this.servers));
    }

    _wireUi() {
        // Initial server list rendering is done after connect.
    }

    async _connectAll() {
        // Dispose any existing clients
        for (const s of this.servers) {
            this.aggregator.remove(s);
        }
        // Build clients
        this.clients = this.servers.map((cfg) => new BackendClient(cfg));
        for (const c of this.clients) this.aggregator.add(c);

        // Initial health probe (parallel)
        await Promise.all(this.clients.map((c) => this._probeClient(c)));
    }

    async _probeClient(client) {
        const ok = await client.healthCheck();
        if (ok) {
            try {
                await client.loadSystem();
            } catch (e) {
                // already marked error in loadSystem
            }
        }
    }

    _startRefreshLoop() {
        if (this.refreshTimer) clearInterval(this.refreshTimer);
        const tick = async () => {
            await this.refresh(false);
        };
        this.refreshTimer = setInterval(tick, REFRESH_INTERVAL_MS);
    }

    async refresh(verbose) {
        await Promise.all(this.clients.map(async (client) => {
            try {
                if (!await client.healthCheck()) {
                    this._updateServerList();
                    return;
                }
                await client.loadSystem();
                await this._loadClientCaches(client);
            } catch (e) {
                // already marked error in client
            }
        }));
        this._notifyViews();
        this._updateServerList();
        document.getElementById('last-update').textContent = `已同步 · ${new Date().toLocaleTimeString('en-GB', { hour12: false })}`;
        if (verbose) ui.toast('已刷新');
    }

    async _loadClientCaches(client) {
        // Fan out the aggregate reads; tolerate failures individually.
        const tasks = [
            ['stats', () => client.getStats()],
            ['topPorts', () => client.getTopPorts(10)],
            ['byIpFamily', () => client.getByIpFamily()],
            ['byService', () => client.getByService()],
            ['byCategory', () => client.getByCategory()],
            ['mapLocations', () => client.getMapLocations(1500)],
            ['results', () => client.getResults(1, 500)],
            ['scanStatus', () => client.getScanStatus()],
        ];
        await Promise.all(tasks.map(async ([key, fn]) => {
            try {
                client.cache[key] = await fn();
            } catch (e) {
                // Leave previous cache in place; do not fail the whole refresh.
                // console.warn('cache', key, e);
            }
        }));
    }

    _notifyViews() {
        const snap = this.aggregator.snapshot();
        snap._topPort = this.aggregator.topPort(snap.online);
        this.lastSnapshot = snap;
        // Sidebar cluster summary always visible
        this._renderSidebar(snap);
        // Re-render current view
        const view = this.views[this.currentView];
        if (view && typeof view.render === 'function') view.render(snap);
    }

    _renderSidebar(snap) {
        const items = document.getElementById('server-list-items');
        if (!items) return;
        if (!this.clients.length) {
            items.innerHTML = '<div class="muted" style="padding:12px;text-align:center">尚无节点</div>';
            return;
        }
        items.innerHTML = this.clients.map((c) => {
            const ports = c.cache.stats?.total_open_records || 0;
            return `
            <div class="server-list-item">
                <span class="pill ${c.state}"></span>
                <div style="flex:1;min-width:0">
                    <div class="name">${escapeHtml(c.label)}</div>
                    <div class="url">${escapeHtml(c.url)}</div>
                </div>
                <div class="meta">${ports.toLocaleString()}</div>
                <button class="remove" onclick="ui.removeServer('${c.id}')">×</button>
            </div>`;
        }).join('');

        // Footer status
        const dot = document.getElementById('status-dot');
        const label = document.getElementById('status-label');
        const online = snap.online.length;
        const total = this.clients.length;
        if (!total) {
            dot.className = 'status-dot';
            label.textContent = '未连接节点';
        } else if (online === total) {
            dot.className = 'status-dot online';
            label.textContent = `${online} 个节点在线`;
        } else if (online === 0) {
            dot.className = 'status-dot offline';
            label.textContent = `全部离线 (${total})`;
        } else {
            dot.className = 'status-dot connecting';
            label.textContent = `${online}/${total} 在线`;
        }
    }

    _updateServerList() {
        if (this.lastSnapshot) this._renderSidebar(this.lastSnapshot);
    }

    exportAll(fmt) {
        if (!this.clients.length) {
            ui.toast('无可用节点', 'error');
            return;
        }
        // Open each server's export endpoint in a new tab. Simple and
        // reliable — the user gets N downloads they can then merge.
        for (const c of this.clients) {
            window.open(c.exportUrl(fmt), '_blank');
        }
        ui.toast(`已为 ${this.clients.length} 个节点发起 ${fmt.toUpperCase()} 导出`, 'success');
    }

    addServer({ id, label, url, provider, latitude, longitude }) {
        if (!url) throw new Error('url required');
        if (this.servers.some((s) => normalize(s.url) === normalize(url))) {
            throw new Error('已存在该服务器');
        }
        const cfg = { id: id || url, label: label || url, url, provider, latitude, longitude };
        this.servers.push(cfg);
        this._saveServers();
        const client = new BackendClient(cfg);
        this.clients.push(client);
        this.aggregator.add(client);
        // Probe + initial sync
        this._probeClient(client).then(() => {
            return this._loadClientCaches(client);
        }).then(() => {
            this._notifyViews();
            this._updateServerList();
        });
    }

    removeServer(id) {
        const client = this.clients.find((c) => c.id === id);
        if (!client) return;
        this.clients = this.clients.filter((c) => c !== client);
        this.servers = this.servers.filter((s) => s.id !== id);
        this.aggregator.remove(client);
        this._saveServers();
        this._notifyViews();
        this._updateServerList();
    }
}

function normalize(u) {
    return u.replace(/\/+$/, '').replace(/\/api\/v\d+$/i, '').toLowerCase();
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// UI helper used by inline event handlers.
const ui = {
    switchView(name) {
        app.currentView = name;
        document.querySelectorAll('.view').forEach((el) => el.style.display = 'none');
        const target = document.getElementById('view-' + name);
        if (target) target.style.display = '';
        document.querySelectorAll('.nav-item').forEach((el) => el.classList.toggle('active', el.dataset.view === name));
        const titles = {
            overview: ['/ OVERVIEW', '分布式资产全景'],
            map: ['/ MAP', '全球 IP 地图'],
            services: ['/ SERVICES', '服务类型浏览'],
            family: ['/ IP FAMILY', 'IPv4 / IPv6 拆分'],
            servers: ['/ NODES', '节点详情'],
            results: ['/ RESULTS', '聚合结果明细'],
            scan: ['/ SCAN CONTROL', '分布式扫描控制'],
        };
        const [kicker, title] = titles[name] || ['', ''];
        document.getElementById('view-kicker').textContent = kicker;
        document.getElementById('view-title').textContent = title;
        // Re-render
        if (app.lastSnapshot) {
            const view = app.views[name];
            if (view && typeof view.render === 'function') view.render(app.lastSnapshot);
        }
    },

    onSearch(value) {
        const view = app.views.results;
        view.setSearch(value);
        if (app.lastSnapshot) view.render(app.lastSnapshot);
    },

    page(d) {
        const view = app.views.results;
        view.pageStep(d);
        if (app.lastSnapshot) view.render(app.lastSnapshot);
    },

    openServerDialog() {
        document.getElementById('server-dialog').style.display = 'flex';
    },

    closeServerDialog() {
        document.getElementById('server-dialog').style.display = 'none';
    },

    saveServer() {
        const url = document.getElementById('srv-url').value.trim();
        const name = document.getElementById('srv-name').value.trim();
        const provider = document.getElementById('srv-provider').value.trim();
        const lat = parseFloat(document.getElementById('srv-lat').value);
        const lng = parseFloat(document.getElementById('srv-lng').value);
        try {
            app.addServer({
                id: name || undefined,
                label: name || undefined,
                url,
                provider: provider || undefined,
                latitude: Number.isFinite(lat) ? lat : undefined,
                longitude: Number.isFinite(lng) ? lng : undefined,
            });
            this.closeServerDialog();
            ui.toast('已添加节点，开始同步', 'success');
            document.getElementById('srv-url').value = '';
            document.getElementById('srv-name').value = '';
            document.getElementById('srv-provider').value = '';
            document.getElementById('srv-lat').value = '';
            document.getElementById('srv-lng').value = '';
        } catch (e) {
            ui.toast(e.message || '添加失败', 'error');
        }
    },

    removeServer(id) {
        app.removeServer(id);
        ui.toast('已移除节点');
    },

    focusServer(id) {
        this.switchView('servers');
    },

    async scanStart() {
        const sel = document.getElementById('scan-target-node');
        const id = sel.value;
        const client = app.clients.find((c) => c.id === id);
        if (!client) {
            ui.toast('请选择节点', 'error');
            return;
        }
        const target = document.getElementById('scan-target').value.trim();
        const ports = document.getElementById('scan-ports').value.trim();
        const timeout = parseInt(document.getElementById('scan-timeout').value, 10) || 800;
        const concurrency = parseInt(document.getElementById('scan-concurrency').value, 10) || 500;
        const skipPrivate = document.getElementById('scan-skip-private').checked;
        const probeService = document.getElementById('scan-probe-service').checked;

        let start_ip, end_ip;
        if (target.includes('/')) {
            // Best-effort CIDR expansion: only support /24 and smaller for the
            // backend's start_ip/end_ip pair.
            try {
                const [base, maskStr] = target.split('/');
                const mask = parseInt(maskStr, 10);
                if (mask < 8 || mask > 32) throw new Error('CIDR 仅支持 /8-/32');
                const hostBits = 32 - mask;
                const baseInt = ipv4ToInt(base);
                const startInt = baseInt;
                const endInt = baseInt + (1 << hostBits) - 1;
                start_ip = intToIpv4(startInt);
                end_ip = intToIpv4(endInt);
            } catch (e) {
                ui.toast('CIDR 解析失败: ' + e.message, 'error');
                return;
            }
        } else if (target.includes('-')) {
            [start_ip, end_ip] = target.split('-').map((s) => s.trim());
        } else {
            start_ip = end_ip = target;
        }

        try {
            await client.startScan({
                start_ip,
                end_ip,
                ports,
                timeout,
                concurrency,
                skip_private: skipPrivate,
                syn: false,
                probe_service: probeService,
            });
            ui.toast(`已在 ${client.label} 发起扫描`, 'success');
            await app.refresh(false);
        } catch (e) {
            ui.toast('扫描发起失败: ' + (e.message || ''), 'error');
        }
    },

    async scanStop() {
        const sel = document.getElementById('scan-target-node');
        return this.scanStopFor(sel.value);
    },

    async scanStopFor(id) {
        const client = app.clients.find((c) => c.id === id);
        if (!client) return;
        try {
            await client.stopScan();
            ui.toast(`已停止 ${client.label}`, 'success');
            await app.refresh(false);
        } catch (e) {
            ui.toast('停止失败: ' + (e.message || ''), 'error');
        }
    },

    toast(msg, type = 'info', ms = 3500) {
        const el = document.createElement('div');
        el.className = 'toast toast-' + type;
        el.textContent = msg;
        document.getElementById('toast-box').appendChild(el);
        setTimeout(() => el.remove(), ms);
    },
};

function ipv4ToInt(s) {
    return s.split('.').reduce((acc, oct) => (acc * 256) + parseInt(oct, 10), 0) >>> 0;
}
function intToIpv4(n) {
    return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.');
}

const app = new App();
app.init();
