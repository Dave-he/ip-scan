// E2E smoke test: spin up the unified web console's modules against two real
// backends. Verifies BackendClient + Aggregator can read every aggregation
// endpoint exposed under /api/v1 by the Rust backend (including the new
// /ip/{ip}, /stats/by-asn, /stats/by-organization, /assets and
// /snapshots/{ip} endpoints).

import { BackendClient } from '../web/src/api.js';
import { Aggregator } from '../web/src/aggregator.js';

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

    for (const c of clients) {
        const ok = await c.healthCheck();
        assert(ok, `${c.id} healthCheck ok`);
        await c.loadSystem();
        assert(c.system?.protocol === 'ip-scan', `${c.id} system.protocol=ip-scan`);
        assert(c.system?.node_id, `${c.id} system.node_id present`);
    }

    for (const c of clients) {
        const stats = await c.getStats(); c.cache.stats = stats;
        const fam = await c.getByIpFamily(); c.cache.byIpFamily = fam;
        const svc = await c.getByService(); c.cache.byService = svc;
        const cat = await c.getByCategory(); c.cache.byCategory = cat;
        const asn = await c.getByAsn(); c.cache.byAsn = asn;
        const org = await c.getByOrganization(); c.cache.byOrganization = org;
        const mp = await c.getMapLocations(50); c.cache.mapLocations = mp;
        const top = await c.getTopPorts(10); c.cache.topPorts = top;
        const assets = await c.getAssets({ pageSize: 50 }); c.cache.assets = assets;
        assert(typeof stats.total_open_records === 'number', `${c.id} stats.total_open_records is number`);
        assert(fam.ipv4_unique_ips !== undefined, `${c.id} byIpFamily.ipv4_unique_ips present`);
        assert(Array.isArray(svc.services), `${c.id} byService.services is array`);
        assert(Array.isArray(cat.categories), `${c.id} byCategory.categories is array`);
        assert(Array.isArray(asn.asns), `${c.id} byAsn.asns is array`);
        assert(Array.isArray(org.organizations), `${c.id} byOrganization.organizations is array`);
        assert(Array.isArray(mp.locations), `${c.id} mapLocations.locations is array`);
        assert(Array.isArray(top.ports), `${c.id} topPorts.ports is array`);
        assert(Array.isArray(assets.assets), `${c.id} /assets returns an array`);
    }

    const snap = agg.snapshot();
    assert(snap.servers.length === clients.length, 'aggregator snapshot includes all servers');
    assert(snap.online.length > 0, 'aggregator reports at least one online server');
    assert(snap.totals.ports >= 0, 'aggregator totals.ports is non-negative');
    assert(Array.isArray(snap.services), 'aggregator snapshot.services is array');
    assert(Array.isArray(snap.asns), 'aggregator snapshot.asns is array');
    assert(Array.isArray(snap.organizations), 'aggregator snapshot.organizations is array');
    assert(Array.isArray(snap.assets), 'aggregator snapshot.assets is array');

    // IP-detail drill-down: pull detail for one of the IPs we discovered
    const firstIp = snap.assets[0]?.ip;
    if (firstIp) {
        const detail = await clients[0].getIpDetail(firstIp);
        assert(detail.ip === firstIp, `${firstIp} /ip/{ip} returns same ip`);
        assert(Array.isArray(detail.open_ports), `${firstIp} /ip/{ip}.open_ports is array`);
        const snaps = await clients[0].getSnapshots(firstIp);
        assert(Array.isArray(snaps.snapshots), `${firstIp} /snapshots/{ip}.snapshots is array`);
    } else {
        console.log('  skip: no assets discovered; ip-detail drill-down not exercised');
    }

    console.log('PASS: frontend e2e smoke test');
}

main().catch((e) => { console.error('ERROR:', e); process.exit(1); });
