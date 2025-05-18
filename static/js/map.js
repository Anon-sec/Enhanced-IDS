let map;
const markers = {};       // Markers keyed by IP address
let lastClickedMarker = null;

// Initialize the Leaflet map
function initMap() {
    map = L.map('mapContainer', {
        scrollWheelZoom: true,
        minZoom: 2,
        maxZoom: 18,
        maxBounds: [[-85, -180], [85, 180]],
        maxBoundsViscosity: 1.0
    }).setView([20, 0], 2);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; OpenStreetMap contributors'
    }).addTo(map);
}

// Fetch geolocation alerts and add markers for new IPs only
async function fetchMapData() {
    try {
        const response = await fetch('/map_data');
        const data = await response.json();

        data.forEach(({ ip, lat, lon, alert }) => {
            if (!markers[ip]) {
                const marker = L.marker([lat, lon]).addTo(map);
                marker.bindPopup(`<b>${alert}</b><br>Source: ${ip}`);
                markers[ip] = marker;
            }
        });

        updateAlertList(data);
    } catch (error) {
        console.error('Failed to fetch map data:', error);
    }
}

// Populate the alert list with clickable items to zoom on map markers
function updateAlertList(data) {
    const alertList = document.getElementById('alertList');
    alertList.innerHTML = '';

    data.forEach(({ ip, lat, lon, alert }) => {
        const li = document.createElement('li');
        li.textContent = `${alert} from ${ip}`;
        li.onclick = () => {
            if (lastClickedMarker) {
                lastClickedMarker.setIcon(new L.Icon.Default());
            }
            map.setView([lat, lon], 6);
            markers[ip].openPopup();
            lastClickedMarker = markers[ip];
        };
        alertList.appendChild(li);
    });
}

// Initialize map and fetch data immediately
initMap();
fetchMapData();
