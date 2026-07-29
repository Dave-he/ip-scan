// Map view: renders geo-located IPs as Leaflet markers.

export class MapView {
    constructor(root) {
        this.root = root;
        this.map = null;
        this.markers = [];
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
        // Invalidate size after layout
        setTimeout(() => this.map && this.map.invalidateSize(), 250);
    }

    render(state) {
        this.ensureMap();
        if (!this.map) return;

        // Clear existing markers
        for (const m of this.markers) m.remove();
        this.markers = [];

        const locations = state.geoLocations;
        document.getElementById('map-marker-count').textContent = locations.length;
        document.getElementById('map-service-count').textContent = locations.reduce((a, l) => a + (l.open_ports || 0), 0);

        const empty = document.getElementById('map-empty');
        if (empty) empty.style.display = locations.length ? 'none' : 'flex';

        for (const loc of locations) {
            if (loc.latitude == null || loc.longitude == null) continue;
            const m = L.circleMarker([loc.latitude, loc.longitude], {
                radius: 4 + Math.min(8, Math.log2(1 + (loc.open_ports || 1))),
                color: '#6de4ff',
                fillColor: '#a47cff',
                fillOpacity: 0.7,
                weight: 1,
            }).addTo(this.map);
            m.bindPopup(this._popup(loc));
            this.markers.push(m);
        }

        // Resize after view switch
        setTimeout(() => this.map && this.map.invalidateSize(), 50);
    }

    _popup(loc) {
        return `
            <div style="min-width:200px">
                <strong>${escapeHtml(loc.ip)}</strong><br>
                <span style="color:#8995b3">${escapeHtml(loc._serverLabel || '')}</span><br>
                ${escapeHtml(loc.country || '')} ${escapeHtml(loc.city || '')}<br>
                <span style="color:#6de4ff">${loc.open_ports || 0}</span> 个开放端口
                ${loc.top_service ? `<br>主要服务: <b>${escapeHtml(loc.top_service)}</b>` : ''}
            </div>
        `;
    }
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
