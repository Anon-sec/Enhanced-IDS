let threatChart;       // Bar chart instance for threat levels
let alertsChart;       // Line chart instance for alerts over time
let currentPage = 1;   // Current page number for alerts pagination
const alertsPerPage = 5;
let alerts = [];       // All fetched alerts

// Fetch alerts from server and display current page with pagination
async function fetchAlerts() {
    try {
        const response = await fetch('/alerts');
        alerts = await response.json();

        renderAlertsPage();
        updatePaginationControls();
    } catch (error) {
        console.error('Failed to fetch alerts:', error);
    }
}

// Render alerts of the current page inside the table body
function renderAlertsPage() {
    const alertTableBody = document.querySelector('#alertTable tbody');
    alertTableBody.innerHTML = '';

    const startIdx = (currentPage - 1) * alertsPerPage;
    const currentPageAlerts = alerts.slice(startIdx, startIdx + alertsPerPage);

    currentPageAlerts.forEach(({ alert, ip, severity, location }) => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td><b>${alert}</b></td>
            <td><a href="https://www.virustotal.com/gui/ip-address/${ip}/details" target="_blank" rel="noopener noreferrer">${ip}</a></td>
            <td>${severity}</td>
            <td>${location}</td>
        `;
        alertTableBody.appendChild(row);
    });

    document.getElementById('pageNumber').textContent = `Page ${currentPage}`;
}

// Enable/disable pagination buttons based on current page
function updatePaginationControls() {
    const totalPages = Math.ceil(alerts.length / alertsPerPage);
    document.getElementById('prevPage').disabled = currentPage <= 1;
    document.getElementById('nextPage').disabled = currentPage >= totalPages;
}

// Handle pagination button clicks
function changePage(direction) {
    const totalPages = Math.ceil(alerts.length / alertsPerPage);
    currentPage = Math.min(Math.max(currentPage + direction, 1), totalPages);
    renderAlertsPage();
    updatePaginationControls();
}

// Filter alerts displayed in the table based on search input
function filterAlerts() {
    const searchValue = document.getElementById('searchBar').value.toLowerCase();
    const rows = document.querySelectorAll('#alertTable tbody tr');

    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchValue) ? '' : 'none';
    });
}

// Fetch threat data and create/update bar chart
async function fetchThreatChartData() {
    try {
        const response = await fetch('/chart_data');
        const { High, Medium, Low } = await response.json();

        const dataValues = [High, Medium, Low];

        if (!threatChart) {
            const ctx = document.getElementById('threatChart').getContext('2d');
            threatChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: [''],
                    datasets: [
                        { label: 'High', data: [High], backgroundColor: 'red' },
                        { label: 'Medium', data: [Medium], backgroundColor: 'orange' },
                        { label: 'Low', data: [Low], backgroundColor: 'yellow' }
                    ]
                },
                options: {
                    responsive: true,
                    animation: { duration: 300 },
                    scales: {
                        y: { beginAtZero: true, precision: 0 },
                        x: {
                            title: {
                                display: true,
                                text: 'Risk Classification of Threats',
                                font: { weight: 'bold', size: 16 }
                            }
                        }
                    }
                }
            });
        } else {
            threatChart.data.datasets.forEach((dataset, idx) => {
                dataset.data = [dataValues[idx]];
            });
            threatChart.update();
        }
    } catch (error) {
        console.error('Failed to fetch threat chart data:', error);
    }
}

// Fetch alerts-over-time data and create/update line chart
async function fetchAlertsOverTimeChart() {
    try {
        const response = await fetch('/alerts_over_time');
        const data = await response.json();

        const ctx = document.getElementById('alertsOverTimeChart').getContext('2d');

        if (!alertsChart) {
            alertsChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.labels,
                    datasets: [{
                        label: 'Alerts Over Time',
                        data: data.counts,
                        fill: false,
                        borderColor: 'blue',
                        tension: 0.3
                    }]
                },
                options: {
                    responsive: true,
                    animation: { duration: 300 },
                    scales: {
                        x: {
                            title: {
                                display: true,
                                text: 'Time',
                                font: { weight: 'bold', size: 14 }
                            }
                        },
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Number of Alerts',
                                font: { weight: 'bold', size: 14 }
                            }
                        }
                    }
                }
            });
        } else {
            alertsChart.data.labels = data.labels;
            alertsChart.data.datasets[0].data = data.counts;
            alertsChart.update();
        }
    } catch (error) {
        console.error('Failed to fetch alerts over time:', error);
    }
}

// Update the map view based on alert IP clicked
async function updateMapOnAlert(alertText) {
    try {
        const response = await fetch('/map_data');
        const mapData = await response.json();

        const matched = mapData.find(entry => alertText.includes(entry.ip));
        if (matched) {
            updateMap(matched.lat, matched.lon, matched.alert);
        }
    } catch (error) {
        console.error('Failed to update map:', error);
    }
}

// Initial data fetch and set intervals for refreshing data
fetchAlerts();
fetchThreatChartData();
fetchAlertsOverTimeChart();

setInterval(fetchAlerts, 5000);
setInterval(fetchThreatChartData, 5000);
setInterval(fetchAlertsOverTimeChart, 5000);
