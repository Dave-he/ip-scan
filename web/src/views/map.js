// Map view: renders geo-located IPs as Leaflet markers + a distinct
// icon for the cluster nodes themselves. Click an IP -> IP-detail
// panel. Marker size scales with the number of open ports.

export class MapView {
    constructor(root) {
        this.root = root;
        this.map = null;
        this.ipLayer = null;
        this.nodeLayer = null;
        this.markers = [];
        this._listenersAttached = false;
        this._onPopupClick = (ip) => {
            if (window.ui && typeof window.ui.ipDetailOpen === 'function') {
                window.ui.ipDetailOpen(ip);
            }
        };
    }

    ensureMap() {
        if (this.map) return;
        const el = document.getElementById('map');
        if (!el || typeof L === 'undefined') return;
        this.map = L.map(el, {
            worldCopyJump: true,
            zoomControl: true,
            attributionControl: true,
        }).setView([20, 0], 2);
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png', {
            subdomains: 'abcd',
            maxZoom: 18,
            attribution: '© OpenStreetMap contributors © CARTO',
        }).addTo(this.map);
        this.ipLayer = L.layerGroup().addTo(this.map);
        this.nodeLayer = L.layerGroup().addTo(this.map);
        setTimeout(() => this.map && this.map.invalidateSize(), 250);
    }

    render(state) {
        this.ensureMap();
        if (!this.map) return;

        // IP markers
        this.ipLayer.clearLayers();
        const locations = state.geoLocations;
        for (const loc of locations) {
            if (loc.latitude == null || loc.longitude == null) continue;
            const m = L.circleMarker([loc.latitude, loc.longitude], {
                radius: 4 + Math.min(8, Math.log2(1 + (loc.open_ports || 1))),
                color: '#6de4ff',
                fillColor: '#a47cff',
                fillOpacity: 0.7,
                weight: 1,
            });
            m.bindPopup(this._popup(loc));
            m.on('popupopen', (e) => this._wirePopupLinks(e, loc.ip));
            m.addTo(this.ipLayer);
        }

        // Cluster node markers (from each server's identity + location)
        this.nodeLayer.clearLayers();
        for (const s of state.servers) {
            if (s.latitude == null || s.longitude == null) continue;
            const icon = L.divIcon({
                className: 'node-marker',
                html: `<div class="node-marker-inner" title="${escapeHtml(s.label)}"></div>`,
                iconSize: [16, 16],
                iconAnchor: [8, 8],
            });
            const m = L.marker([s.latitude, s.longitude], { icon, zIndexOffset: -100 }).bindPopup(this._nodePopup(s));
            m.addTo(this.nodeLayer);
        }

        // Stats
        const portCount = locations.reduce((a, l) => a + (l.open_ports || 0), 0);
        document.getElementById('map-marker-count').textContent = locations.length;
        document.getElementById('map-service-count').textContent = portCount;
        const empty = document.getElementById('map-empty');
        if (empty) empty.style.display = locations.length ? 'none' : 'flex';

        setTimeout(() => this.map && this.map.invalidateSize(), 50);
    }

    _popup(loc) {
        return `
            <div style="min-width:220px" class="map-popup">
                <strong style="font-family:var(--mono);color:var(--accent)">${escapeHtml(loc.ip)}</strong>
                <span class="muted"> · ${escapeHtml(loc._serverLabel || '')}</span>
                <div class="muted">${escapeHtml(loc.country || '')} ${escapeHtml(loc.city || '')}</div>
                <div><span style="color:#6de4ff">${loc.open_ports || 0}</span> 个开放端口</div>
                ${loc.top_service ? `<div>主要服务: <b>${escapeHtml(loc.top_service)}</b></div>` : ''}
                <a href="#" data-ip="${escapeHtml(loc.ip)}" class="popup-open-ip">查看详情 →</a>
            </div>
        `;
    }

    _nodePopup(s) {
        return `
            <div style="min-width:220px">
                <strong>${escapeHtml(s.label)}</strong>
                <span class="chip">${escapeHtml(s.provider || '')}</span>
                <div class="muted">${escapeHtml(s.url)}</div>
                ${s.latitude != null ? `<div class="muted" style="font-size:11px">${s.latitude.toFixed(3)}, ${s.longitude.toFixed(3)}</div>` : ''}
            </div>
        `;
    }

    _wirePopupLinks(e, ip) {
        const popup = e.popup.getElement();
        if (!popup) return;
        const link = popup.querySelector('.popup-open-ip');
        if (link) {
            link.addEventListener('click', (ev) => {
                ev.preventDefault();
                this._onPopupClick(ip);
                this.map.closePopup();
            });
        }
    }
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
