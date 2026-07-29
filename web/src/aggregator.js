// Aggregates results across multiple BackendClient instances.
// Pure data merging; the views subscribe to `aggregator.snapshot()`.

export class Aggregator {
    constructor() {
        this.servers = []; // BackendClient[]
        this.listeners = new Set();
        this.lastSnapshot = null;
    }

    add(server) {
        this.servers.push(server);
        this._notify();
    }

    remove(server) {
        this.servers = this.servers.filter((s) => s !== server);
        this._notify();
    }

    subscribe(fn) {
        this.listeners.add(fn);
        return () => this.listeners.delete(fn);
    }

    _notify() {
        for (const fn of this.listeners) fn(this.snapshot());
    }

    snapshot() {
        const online = this.servers.filter((s) => s.state === 'online');
        return {
            servers: this.servers,
            online,
            totals: this._totals(online),
            services: this._byService(online),
            categories: this._byCategory(online),
            asns: this._byAsn(online),
            organizations: this._byOrganization(online),
            families: this._byFamily(online),
            geoLocations: this._geoLocations(online),
            results: this._aggregateResults(online),
            assets: this._aggregateAssets(online),
        };
    }

    _byAsn(servers) {
        const merged = new Map();
        for (const s of servers) {
            const v = s.cache.byAsn;
            if (!v || !v.asns) continue;
            for (const e of v.asns) {
                const cur = merged.get(e.asn) || { asn: e.asn, unique_ips: 0, open_ports: 0 };
                cur.unique_ips += e.unique_ips;
                cur.open_ports += e.open_ports;
                merged.set(e.asn, cur);
            }
        }
        return Array.from(merged.values()).sort((a, b) => b.unique_ips - a.unique_ips);
    }

    _byOrganization(servers) {
        const merged = new Map();
        for (const s of servers) {
            const v = s.cache.byOrganization;
            if (!v || !v.organizations) continue;
            for (const e of v.organizations) {
                const cur = merged.get(e.isp) || { isp: e.isp, unique_ips: 0, open_ports: 0 };
                cur.unique_ips += e.unique_ips;
                cur.open_ports += e.open_ports;
                merged.set(e.isp, cur);
            }
        }
        return Array.from(merged.values()).sort((a, b) => b.unique_ips - a.unique_ips);
    }

    /**
     * Aggregate per-server asset lists into a deduplicated set keyed by IP.
     * Each IP keeps the first non-null service/category/risk we find.
     */
    _aggregateAssets(servers) {
        const map = new Map();
        for (const s of servers) {
            const v = s.cache.assets;
            if (!v || !v.assets) continue;
            for (const a of v.assets) {
                const cur = map.get(a.ip) || {};
                // Preserve known-good fields; prefer the first non-empty value
                cur.ip = a.ip;
                cur.ip_type = cur.ip_type || a.ip_type;
                cur.open_ports = Math.max(cur.open_ports || 0, a.open_ports || 0);
                cur.first_seen = cur.first_seen || a.first_seen;
                cur.last_seen = cur.last_seen || a.last_seen;
                cur.country = cur.country || a.country;
                cur.city = cur.city || a.city;
                cur.isp = cur.isp || a.isp;
                cur.asn = cur.asn || a.asn;
                cur.reverse_dns = cur.reverse_dns || a.reverse_dns;
                cur.top_service = cur.top_service || a.top_service;
                cur.category = cur.category || a.category;
                cur.risk_score = cur.risk_score == null ? a.risk_score : cur.risk_score;
                if (a.latitude != null) cur.latitude = a.latitude;
                if (a.longitude != null) cur.longitude = a.longitude;
                if (!cur._servers) cur._servers = [];
                if (!cur._servers.includes(s.label)) cur._servers.push(s.label);
                map.set(a.ip, cur);
            }
        }
        return Array.from(map.values());
    }

    _totals(servers) {
        let ports = 0;
        let ips = 0;
        const portCount = new Map();
        for (const s of servers) {
            if (!s.cache.stats) continue;
            ports += s.cache.stats.total_open_records || 0;
            ips = Math.max(ips, s.cache.stats.unique_ips || 0);
        }
        // ips is per-server so we approximate by summing distinct from /results
        // and recompute if results available; for the sidebar cluster summary
        // we use unique ips by IP across all servers' cached /results.
        return { ports, ips, portCount, serverCount: servers.length };
    }

    _byService(servers) {
        // Merge per-server service aggregates; keys are service names.
        const merged = new Map();
        for (const s of servers) {
            const v = s.cache.byService;
            if (!v || !v.services) continue;
            for (const e of v.services) {
                const cur = merged.get(e.service_name) || { service_name: e.service_name, unique_ips: 0, open_ports: 0 };
                cur.unique_ips += e.unique_ips;
                cur.open_ports += e.open_ports;
                merged.set(e.service_name, cur);
            }
        }
        return Array.from(merged.values()).sort((a, b) => b.unique_ips - a.unique_ips);
    }

    _byCategory(servers) {
        const merged = new Map();
        for (const s of servers) {
            const v = s.cache.byCategory;
            if (!v || !v.categories) continue;
            for (const e of v.categories) {
                const cur = merged.get(e.category) || { category: e.category, unique_ips: 0 };
                cur.unique_ips += e.unique_ips;
                merged.set(e.category, cur);
            }
        }
        return Array.from(merged.values()).sort((a, b) => b.unique_ips - a.unique_ips);
    }

    _byFamily(servers) {
        const fam = { ipv4_unique_ips: 0, ipv6_unique_ips: 0, ipv4_open_ports: 0, ipv6_open_ports: 0 };
        for (const s of servers) {
            const v = s.cache.byIpFamily;
            if (!v) continue;
            fam.ipv4_unique_ips += v.ipv4_unique_ips || 0;
            fam.ipv6_unique_ips += v.ipv6_unique_ips || 0;
            fam.ipv4_open_ports += v.ipv4_open_ports || 0;
            fam.ipv6_open_ports += v.ipv6_open_ports || 0;
        }
        return fam;
    }

    _geoLocations(servers) {
        const out = [];
        for (const s of servers) {
            const v = s.cache.mapLocations;
            if (!v || !v.locations) continue;
            for (const loc of v.locations) {
                out.push({ ...loc, _serverId: s.id, _serverLabel: s.label });
            }
        }
        return out;
    }

    _aggregateResults(servers) {
        // Build deduped (ip, port) results, tagging each with its source server.
        const map = new Map();
        for (const s of servers) {
            const v = s.cache.results;
            if (!v || !v.results) continue;
            for (const r of v.results) {
                const key = `${r.ip_address}:${r.port}`;
                if (!map.has(key)) {
                    map.set(key, { ...r, _servers: [s.label] });
                } else {
                    const cur = map.get(key);
                    if (!cur._servers.includes(s.label)) cur._servers.push(s.label);
                }
            }
        }
        return Array.from(map.values());
    }

    topPort(servers) {
        const portCount = new Map();
        for (const s of servers) {
            const v = s.cache.topPorts;
            if (!v || !v.ports) continue;
            for (const p of v.ports) {
                portCount.set(p.port, (portCount.get(p.port) || 0) + p.open_count);
            }
        }
        if (portCount.size === 0) return null;
        const top = Array.from(portCount.entries()).sort((a, b) => b[1] - a[1])[0];
        return { port: top[0], count: top[1] };
    }
}
