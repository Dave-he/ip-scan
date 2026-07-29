# ip-scan Distributed Frontend

A standalone web console that connects to one or more `ip-scan` scanner nodes,
aggregates their results, and renders them in 5+ different views:

- **总览 / Overview** — cluster-wide metrics, per-node heatmap, top services
- **地图 / Map** — global Leaflet map of every geo-located IP
- **服务类型 / Services** — grouped by detected service_name
- **IP 族 / Family** — IPv4 vs IPv6 + asset-category breakdown
- **节点列表 / Servers** — per-node status, target range, latest stats
- **结果明细 / Results** — deduped (ip, port) table with search & pagination
- **扫描控制 / Scan Control** — start/stop scans on individual nodes

## Run locally

```bash
# 1. Start one or more scanner nodes (each needs --node-* identity flags)
./ip-scan --api-only \
    --node-id ali-sh --node-label "ali-shanghai" \
    --node-latitude 31.23 --node-longitude 121.47 \
    --api-port 9090
./ip-scan --api-only \
    --node-id tx-bj --node-label "tx-beijing" \
    --node-latitude 39.90 --node-longitude 116.40 \
    --api-port 9090

# 2. Start the frontend
node ../scripts/serve-frontend.mjs 4000
# 3. Open http://127.0.0.1:4000/, click + 服务器 to add the two URLs
```

The frontend stores node URLs in browser localStorage so subsequent visits pick
up where you left off.

## Architecture

```text
index.html ─── src/app.js (state + router)
                  ├─ src/api.js        (BackendClient)
                  ├─ src/aggregator.js (cross-node merge)
                  └─ src/views/*.js    (per-view render classes)
```

`BackendClient` is a thin wrapper around the ip-scan HTTP API; it caches every
aggregate per-server so the aggregator can recompute the cluster snapshot
without re-fetching.

`Aggregator.snapshot()` produces a unified shape that every view consumes:

```ts
{
  servers: BackendClient[],
  online: BackendClient[],          // state === 'online'
  totals: { ports, ips, portCount, serverCount },
  services: [{ service_name, unique_ips, open_ports }],   // merged
  categories: [{ category, unique_ips }],                  // merged
  families: { ipv4_unique_ips, ipv6_unique_ips, ... },     // merged
  geoLocations: [{ ip, latitude, longitude, open_ports, top_service, _serverLabel }],
  results: [{ ip_address, port, country, city, _servers }],   // deduped (ip, port)
}
```

Adding a new view is a 50-line ES module that takes a constructor arg and
implements `render(state)`.

## Files

- `index.html` — page shell with sidebar nav and view containers
- `css/style.css` — dark cyber theme, shared across all views
- `src/app.js` — bootstraps, wires views, polls every 8s
- `src/api.js` — BackendClient (healthCheck, loadSystem, fetchJson, scan control)
- `src/aggregator.js` — pure-data merge across N BackendClient caches
- `src/views/overview.js` — metrics + heatmap + service bar
- `src/views/map.js` — Leaflet map of geoLocations
- `src/views/services.js` — service cards
- `src/views/family.js` — IPv4/IPv6 + category cards
- `src/views/servers.js` — per-node detail cards
- `src/views/results.js` — deduped (ip, port) table + search + paging
- `src/views/scan.js` — start/stop controls + live per-node status

## Tests

```bash
node --check src/app.js && node --check src/aggregator.js
node ../scripts/test-frontend-e2e.mjs   # starts two backends, exercises API
```
