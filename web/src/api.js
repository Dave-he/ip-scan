// API client for a single ip-scan backend.
// Wraps fetch with health-aware error handling.
//
// All endpoints live under /api/v1. The constructor stores the raw base URL
// (no /api/v1 suffix) and every fetch prepends /api/v1.

const API_PREFIX = '/api/v1';

export class BackendClient {
    constructor({ id, label, url, provider, latitude, longitude }) {
        this.id = id;
        this.label = label || id;
        this.provider = provider || '';
        this.url = normalizeUrl(url);
        this.latitude = latitude ?? null;
        this.longitude = longitude ?? null;
        this.system = null;
        this.lastError = null;
        this.lastSyncAt = null;
        this.state = 'connecting'; // connecting | online | offline | error
        // Per-server cached aggregates
        this.cache = {
            results: null,
            services: null,
            stats: null,
            topPorts: null,
            byIpFamily: null,
            byService: null,
            byCategory: null,
            byAsn: null,
            byOrganization: null,
            mapLocations: null,
            assets: null,
            scanStatus: null,
            scanHistory: null,
        };
    }

    matches(otherUrl) {
        return this.url === normalizeUrl(otherUrl);
    }

    async healthCheck() {
        try {
            const r = await fetch(this.url + API_PREFIX + '/healthz', { cache: 'no-store' });
            if (!r.ok) {
                this.state = 'error';
                this.lastError = `healthz ${r.status}`;
                return false;
            }
            const j = await r.json();
            if (j.database !== 'ok') {
                this.state = 'error';
                this.lastError = 'database error';
                return false;
            }
            return true;
        } catch (e) {
            this.state = 'offline';
            this.lastError = e.message;
            return false;
        }
    }

    async loadSystem() {
        try {
            const r = await fetch(this.url + API_PREFIX + '/system', { cache: 'no-store' });
            if (!r.ok) throw new Error(`system ${r.status}`);
            const j = await r.json();
            this.system = j;
            if (j.protocol !== 'ip-scan' || j.api_version !== 'v1') {
                throw new Error('protocol mismatch');
            }
            // Backfill identity from server-reported values if missing client-side.
            this.id = this.id || j.node_id || this.url;
            this.label = this.label || j.node_label || this.id;
            this.provider = this.provider || j.node_provider || '';
            if (this.latitude == null && j.node_latitude != null) this.latitude = j.node_latitude;
            if (this.longitude == null && j.node_longitude != null) this.longitude = j.node_longitude;
            this.state = 'online';
            this.lastError = null;
            this.lastSyncAt = new Date();
            return j;
        } catch (e) {
            this.state = 'error';
            this.lastError = e.message;
            throw e;
        }
    }

    async fetchJson(path) {
        const r = await fetch(this.url + API_PREFIX + path, { cache: 'no-store' });
        if (!r.ok) {
            const detail = await r.json().catch(() => ({}));
            throw new Error(detail.error || `HTTP ${r.status}`);
        }
        return r.json();
    }

    async getStats() { return this.fetchJson('/stats'); }
    async getTopPorts(limit = 10) { return this.fetchJson(`/stats/top-ports?limit=${limit}`); }
    async getByIpFamily() { return this.fetchJson('/stats/by-ip-family'); }
    async getByService() { return this.fetchJson('/stats/by-service'); }
    async getByCategory() { return this.fetchJson('/stats/by-category'); }
    async getMapLocations(limit = 1000) { return this.fetchJson(`/map/locations?limit=${limit}`); }
    async getByAsn() { return this.fetchJson('/stats/by-asn'); }
    async getByOrganization() { return this.fetchJson('/stats/by-organization'); }
    async getIpDetail(ip) { return this.fetchJson('/ip/' + encodeURIComponent(ip)); }
    async getSnapshots(ip) { return this.fetchJson('/snapshots/' + encodeURIComponent(ip)); }
    async getAssets(opts = {}) {
        const params = new URLSearchParams();
        params.set('page', opts.page || 1);
        params.set('page_size', opts.pageSize || 100);
        if (opts.country) params.set('country', opts.country);
        if (opts.service) params.set('service', opts.service);
        if (opts.category) params.set('category', opts.category);
        if (opts.minRisk) params.set('min_risk', opts.minRisk);
        return this.fetchJson('/assets?' + params.toString());
    }
    async getResults(page = 1, pageSize = 50, search = '') {
        const params = new URLSearchParams({ page, page_size: pageSize });
        if (search) params.set('ip', search);
        return this.fetchJson(`/results?${params.toString()}`);
    }
    async getServiceSummaries(page = 1, pageSize = 50) {
        return this.fetchJson(`/services?page=${page}&page_size=${pageSize}`);
    }
    async getScanStatus() { return this.fetchJson('/scan/status'); }
    async getScanHistory() { return this.fetchJson('/scan/history'); }
    async startScan(req) {
        return this.fetchJson('/scan/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req),
        });
    }
    async stopScan() {
        return this.fetchJson('/scan/stop', { method: 'POST' });
    }
    exportUrl(fmt) { return `${this.url}${API_PREFIX}/export/${fmt}`; }
}

function normalizeUrl(raw) {
    let u = (raw || '').trim();
    if (!u) throw new Error('empty url');
    if (!/^https?:\/\//i.test(u)) u = 'http://' + u;
    u = u.replace(/\/+$/, '');
    // Strip /api/v1 suffix if accidentally included (the client always re-adds it)
    u = u.replace(/\/api\/v\d+$/i, '');
    return u;
}
