// Main entrypoint for the IP-Scan distributed frontend.
// Wires the connection manager, aggregator, views, and UI shell together.

import { BackendClient } from './api.js';
import { Aggregator } from './aggregator.js';
import { DEFAULT_NODES } from './config.js';
import { OverviewView } from './views/overview.js';
import { MapView } from './views/map.js';
import { ServicesView } from './views/services.js';
import { FamilyView } from './views/family.js';
import { ServersView } from './views/servers.js';
import { ResultsView } from './views/results.js';
import { ScanView } from './views/scan.js';
import { AssetsView } from './views/assets.js';
import { IpDetailView } from './views/ip-detail.js';

const STORAGE_KEY = 'ipscan-distributed-servers-v1';
const WELCOME_KEY = 'ipscan-welcome-shown-v1';
const REFRESH_INTERVAL_MS = 8000;

class App {
    constructor() {
        this.aggregator = new Aggregator();
        this.servers = [];
        this.ipDetail = new IpDetailView(document.getElementById('ip-detail'));
        this.views = {
            overview: new OverviewView(document),
            map: new MapView(document),
            services: new ServicesView(document),
            family: new FamilyView(document),
            assets: new AssetsView(document),
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
        await this._connectAll();
        this._notifyViews();
        this._startRefreshLoop();
        this._maybeShowWelcome();
        window.app = this;
        window.ui = ui;
    }

    _loadServers() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            const stored = raw ? JSON.parse(raw) : null;
            if (Array.isArray(stored) && stored.length > 0) {
                this.servers = stored;
                return;
            }
        } catch (e) { /* fall through */ }
        const runtime = (typeof window !== 'undefined' && Array.isArray(window.IPSCAN_DEFAULT_NODES))
            ? window.IPSCAN_DEFAULT_NODES
            : DEFAULT_NODES;
        this.servers = JSON.parse(JSON.stringify(runtime));
        try { this._saveServers(); } catch (_) { /* localStorage may be disabled */ }
    }

    _saveServers() {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(this.servers));
    }

    async _connectAll() {
        for (const s of this.servers) this.aggregator.remove(s);
        this.clients = this.servers.map((cfg) => new BackendClient(cfg));
        for (const c of this.clients) this.aggregator.add(c);
        await Promise.all(this.clients.map((c) => this._probeClient(c)));
    }

    async _probeClient(client) {
        const ok = await client.healthCheck();
        if (ok) {
            try { await client.loadSystem(); } catch (e) { /* marked in loadSystem */ }
        }
    }

    _startRefreshLoop() {
        if (this.refreshTimer) clearInterval(this.refreshTimer);
        this.refreshTimer = setInterval(() => this.refresh(false), REFRESH_INTERVAL_MS);
    }

    _maybeShowWelcome() {
        try {
            if (localStorage.getItem(WELCOME_KEY)) return;
            localStorage.setItem(WELCOME_KEY, '1');
            const el = document.getElementById('welcome-dialog');
            if (el) el.style.display = 'flex';
        } catch (_) { /* localStorage may be disabled */ }
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
            } catch (e) { /* marked in client */ }
        }));
        this._notifyViews();
        this._updateServerList();
        document.getElementById('last-update').textContent =
            `已同步 · ${new Date().toLocaleTimeString('en-GB', { hour12: false })}`;
        if (verbose) ui.toast('已刷新');
    }

    async _loadClientCaches(client) {
        const tasks = [
            ['stats', () => client.getStats()],
            ['topPorts', () => client.getTopPorts(10)],
            ['byIpFamily', () => client.getByIpFamily()],
            ['byService', () => client.getByService()],
            ['byCategory', () => client.getByCategory()],
            ['byAsn', () => client.getByAsn()],
            ['byOrganization', () => client.getByOrganization()],
            ['mapLocations', () => client.getMapLocations(1500)],
            ['results', () => client.getResults(1, 500)],
            ['assets', () => client.getAssets({ pageSize: 200 })],
            ['scanStatus', () => client.getScanStatus()],
        ];
        await Promise.all(tasks.map(async ([key, fn]) => {
            try { client.cache[key] = await fn(); }
            catch (e) { /* leave previous cache */ }
        }));
    }

    _notifyViews() {
        const snap = this.aggregator.snapshot();
        snap._topPort = this.aggregator.topPort(snap.online);
        this.lastSnapshot = snap;
        this._renderSidebar(snap);
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
            const ips = c.cache.stats?.unique_ips || 0;
            return `
            <div class="server-list-item">
                <span class="pill ${c.state}"></span>
                <div>
                    <strong>${escapeHtml(c.label)}</strong>
                    <div class="muted" style="font-size:11px">${escapeHtml(c.url)}</div>
                    <div class="muted" style="font-size:11px">${ports.toLocaleString()} 端口 · ${ips.toLocaleString()} IP</div>
                </div>
                <button class="text-btn" title="移除" onclick="ui.removeServer('${c.id}')">×</button>
            </div>`;
        }).join('');
    }

    _updateServerList() {
        if (this.lastSnapshot) this._renderSidebar(this.lastSnapshot);
    }

    addServer(cfg) {
        if (!cfg || !cfg.url) throw new Error('请填写 API 地址');
        const id = cfg.id || ('srv-' + Math.random().toString(36).slice(2, 8));
        const full = { id, label: cfg.label || id, url: cfg.url, provider: cfg.provider || '', latitude: cfg.latitude, longitude: cfg.longitude };
        this.servers.push(full);
        this._saveServers();
        const client = new BackendClient(full);
        this.clients = this.clients || [];
        this.clients.push(client);
        this.aggregator.add(client);
        this._probeClient(client).then(() => this.refresh(true));
    }

    removeServer(id) {
        this.servers = this.servers.filter((s) => s.id !== id);
        this._saveServers();
        const client = (this.clients || []).find((c) => c.id === id);
        if (client) {
            this.aggregator.remove(client);
            this.clients = this.clients.filter((c) => c !== id && c !== client);
        }
        this._notifyViews();
    }

    exportAll(fmt) {
        if (!this.clients || !this.clients.length) {
            ui.toast('未连接节点', 'error');
            return;
        }
        // Open the first node's export URL in a new tab. Aggregated export is
        // a frontend concern; operators can combine with `jq` / `csvkit`.
        const url = this.clients[0].exportUrl(fmt);
        window.open(url, '_blank');
        ui.toast(`已打开 ${fmt.toUpperCase()} 导出`, 'success');
    }
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const ui = {
    switchView(name) {
        app.currentView = name;
        document.querySelectorAll('.view').forEach((v) => v.style.display = 'none');
        document.querySelectorAll('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
        const view = document.getElementById('view-' + name);
        if (view) view.style.display = '';
        const titles = {
            overview: '分布式资产全景', map: '全球 IP 地图', services: '服务类型浏览',
            family: 'IP 族拆分', assets: '资产库', servers: '节点详情',
            results: '结果明细', scan: '扫描任务配置',
        };
        const kicker = { overview: '/ OVERVIEW', map: '/ GLOBAL MAP', services: '/ BY SERVICE', family: '/ IP FAMILY', assets: '/ ASSET LIBRARY', servers: '/ NODE LIST', results: '/ AGGREGATED RESULTS', scan: '/ SCAN CONTROL' };
        const t = document.getElementById('view-title'); if (t) t.textContent = titles[name] || name;
        const k = document.getElementById('view-kicker'); if (k) k.textContent = kicker[name] || '/' + name.toUpperCase();
        if (app.lastSnapshot) {
            const v = app.views[name];
            if (v) v.render(app.lastSnapshot);
        }
        // Always close the IP-detail panel when switching views so it doesn't
        // accidentally overlap a different layout.
        app.ipDetail.hide();
    },
    openServerDialog() { document.getElementById('server-dialog').style.display = 'flex'; },
    closeServerDialog() { document.getElementById('server-dialog').style.display = 'none'; },
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
        } catch (e) { ui.toast(e.message || '添加失败', 'error'); }
    },
    removeServer(id) { app.removeServer(id); ui.toast('已移除节点'); },
    focusServer(id) { this.switchView('servers'); },
    closeWelcome() { document.getElementById('welcome-dialog').style.display = 'none'; },
    onSearch(v) {
        if (app.views.results.setSearch) app.views.results.setSearch(v);
        if (app.lastSnapshot) app.views.results.render(app.lastSnapshot);
    },
    onServiceFilter(v) {
        if (app.views.results.setService) app.views.results.setService(v);
        if (app.lastSnapshot) app.views.results.render(app.lastSnapshot);
    },
    assetsSearch(v) {
        app.views.assets.setSearch(v);
        if (app.lastSnapshot) app.views.assets.render(app.lastSnapshot);
    },
    assetsService(v) {
        app.views.assets.setService(v);
        if (app.lastSnapshot) app.views.assets.render(app.lastSnapshot);
    },
    assetsCountry(v) {
        app.views.assets.setCountry(v);
        if (app.lastSnapshot) app.views.assets.render(app.lastSnapshot);
    },
    assetsRisk(v) {
        app.views.assets.setMinRisk(parseInt(v, 10) || 0);
        if (app.lastSnapshot) app.views.assets.render(app.lastSnapshot);
    },
    page(d) {
        app.views.results.pageStep(d);
        if (app.lastSnapshot) app.views.results.render(app.lastSnapshot);
    },
    scanApplyPreset(id) {
        if (app.views.scan.applyPreset) app.views.scan.applyPreset(id);
    },
    async ipDetailOpen(ip) {
        // Prefer the first online client; fall back to any client.
        const client = (app.clients || []).find((c) => c.state === 'online') || (app.clients || [])[0];
        if (!client) { ui.toast('请先连接节点', 'error'); return; }
        app.ipDetail.show(ip, client);
    },
    ipDetailClose() { app.ipDetail.hide(); },
    copyText(text) {
        try {
            navigator.clipboard.writeText(text);
            ui.toast('已复制: ' + text, 'success', 1500);
        } catch (_) { ui.toast('复制失败', 'error'); }
    },
    async scanStart() {
        const sel = document.getElementById('scan-target-node');
        const id = sel.value;
        const client = app.clients.find((c) => c.id === id);
        if (!client) { ui.toast('请选择节点', 'error'); return; }
        const target = document.getElementById('scan-target').value.trim();
        const ports = document.getElementById('scan-ports').value.trim();
        const timeout = parseInt(document.getElementById('scan-timeout').value, 10) || 800;
        const concurrency = parseInt(document.getElementById('scan-concurrency').value, 10) || 500;
        const skipPrivate = document.getElementById('scan-skip-private').checked;
        const probeService = document.getElementById('scan-probe-service').checked;
        let start_ip, end_ip;
        if (target.includes('/')) {
            try {
                const [base, maskStr] = target.split('/');
                const mask = parseInt(maskStr, 10);
                if (mask < 8 || mask > 32) throw new Error('CIDR 仅支持 /8-/32');
                const hostBits = 32 - mask;
                const baseInt = ipv4ToInt(base);
                start_ip = intToIpv4(baseInt);
                end_ip = intToIpv4(baseInt + (1 << hostBits) - 1);
            } catch (e) { ui.toast('CIDR 解析失败: ' + e.message, 'error'); return; }
        } else if (target.includes('-')) {
            [start_ip, end_ip] = target.split('-').map((s) => s.trim());
        } else {
            start_ip = end_ip = target;
        }
        try {
            await client.startScan({ start_ip, end_ip, ports, timeout, concurrency, skip_private: skipPrivate, syn: false, probe_service: probeService });
            ui.toast(`已在 ${client.label} 发起扫描`, 'success');
            await app.refresh(false);
        } catch (e) { ui.toast('扫描发起失败: ' + (e.message || ''), 'error'); }
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
        } catch (e) { ui.toast('停止失败: ' + (e.message || ''), 'error'); }
    },
    toast(msg, type = 'info', ms = 3500) {
        const el = document.createElement('div');
        el.className = 'toast toast-' + type;
        el.textContent = msg;
        document.getElementById('toast-box').appendChild(el);
        setTimeout(() => el.remove(), ms);
    },
};

function ipv4ToInt(s) { return s.split('.').reduce((acc, oct) => (acc * 256) + parseInt(oct, 10), 0) >>> 0; }
function intToIpv4(n) { return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.'); }

const app = new App();
app.init();
