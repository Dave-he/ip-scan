// Default distributed nodes for the unified ip-scan web console.
//
// When a fresh browser (no localStorage entry under STORAGE_KEY) opens the
// console, these nodes are auto-loaded so the cluster view is immediately
// populated without going through "+ 服务器". The user can still add /
// remove / replace them; once they edit the sidebar list, their custom
// configuration wins and these defaults are no longer applied.
//
// Override at runtime by setting `window.IPSCAN_DEFAULT_NODES` BEFORE
// app.js executes (e.g. inject a small <script> tag from your reverse
// proxy or embed it inline in index.html for an air-gapped deployment).
//
// Each entry:
//   id        stable node identifier (used as localStorage key, server label)
//   label     human-readable name shown in sidebar / heatmap / map
//   url       base API URL — must NOT include /api/v1 (BackendClient
//             re-adds it via the API_PREFIX constant)
//   provider  optional, shown as a subtitle on the servers view
//   latitude  optional, decimal degrees — used by the map view
//   longitude optional, decimal degrees — used by the map view
export const DEFAULT_NODES = [
    {
        id: 'node-ali',
        label: 'ali-shanghai',
        url: 'http://39.103.188.33:9090',
        provider: 'Aliyun',
        latitude: 31.2304,
        longitude: 121.4737,
    },
    {
        id: 'node-tx',
        label: 'tx-beijing',
        url: 'http://43.133.224.11:9090',
        provider: 'Tencent',
        latitude: 39.9042,
        longitude: 116.4074,
    },
];
