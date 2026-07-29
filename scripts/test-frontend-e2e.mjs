// E2E smoke test: spin up the frontend's modules against a real backend.
// Verifies BackendClient + Aggregator can read the new endpoints.

import { BackendClient } from '../frontend/src/api.js';
import { Aggregator } from '../frontend/src/aggregator.js';

const NODES = [
    { id: 'n1', url: process.env.N1_URL || 'http://127.0.0.1:9301', label: 'n1' },
    { id: 'n2', url: process.env.N2_URL || 'http://127.0.0.1:9302', label: 'n2' },
];

function assert(cond, msg) {
    if (!cond) {
        console.error('FAIL:', msg);
        process.exit(1);
    }
    console.log('  ok:', msg);
}

async function main() {
    const agg = new Aggregator();
    const clients = NODES.map((n) => new BackendClient(n));
    for (const c of clients) agg.add(c);

    // Probe + load caches
    for (const c of clients) {
        const ok = await c.healthCheck();
        assert(ok, `${c.id} healthCheck ok`);
        await c.loadSystem();
        assert(c.system?.protocol === 'ip-scan', `${c.id} system.protocol=ip-scan`);
        assert(c.system?.node_id, `${c.id} system.node_id present`);
    }

    // Pull every aggregation endpoint
    for (const c of clients) {
        const stats = await c.getStats();
        c.cache.stats = stats;
        const fam = await c.getByIpFamily();
        c.cache.byIpFamily = fam;
        const svc = await c.getByService();
        c.cache.byService = svc;
        const cat = await c.getByCategory();
        c.cache.byCategory = cat;
        const mp = await c.getMapLocations(50);
        c.cache.mapLocations = mp;
        const top = await c.getTopPorts(10);
        c.cache.topPorts = top;
        assert(typeof stats.total_open_records === 'number', `${c.id} stats.total_open_records is number`);
        assert(fam.ipv4_unique_ips !== undefined, `${c.id} byIpFamily.ipv4_unique_ips present`);
        assert(Array.isArray(svc.services), `${c.id} byService.services is array`);
        assert(Array.isArray(cat.categories), `${c.id} byCategory.categories is array`);
        assert(Array.isArray(mp.locations), `${c.id} mapLocations.locations is array`);
        assert(Array.isArray(top.ports), `${c.id} topPorts.ports is array`);
    }

    // Aggregator snapshot should merge
    const snap = agg.snapshot();
    assert(snap.servers.length === clients.length, 'aggregator snapshot includes all servers');
    assert(snap.online.length > 0, 'aggregator reports at least one online server');
    assert(snap.totals.ports >= 0, 'aggregator totals.ports is non-negative');
    assert(Array.isArray(snap.services), 'aggregator snapshot.services is array');

    console.log('PASS: frontend e2e smoke test');
}

main().catch((e) => { console.error('ERROR:', e); process.exit(1); });
