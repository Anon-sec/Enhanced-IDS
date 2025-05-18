import time
import scapy.all as scapy
import threading
import requests
from flask import Flask, jsonify, render_template
import winsound
from collections import defaultdict

# -----------------------------------
# Global Variables & Configuration
# -----------------------------------

detected_alerts = []               # Stores all alert data shown on the dashboard
logged_alerts = set()             # Helps prevent duplicate logs
geo_cache = {}                    # Caches IP geolocation results to avoid redundant lookups
log_file = "ids_log.txt"          # File where alerts are logged

# -----------------------------------
# Utility Functions
# -----------------------------------

def get_geoip_info(ip):
    """
    Fetches geolocation data for a given IP address using ip-api.com.
    Returns a tuple: (location string, latitude, longitude)
    """
    if ip in geo_cache:
        return geo_cache[ip]

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        city = response.get("city", "Unknown")
        country = response.get("country", "Unknown")
        lat = response.get("lat", 0)
        lon = response.get("lon", 0)
        geo_cache[ip] = (f"{city}, {country}", lat, lon)
        return geo_cache[ip]
    except:
        return "Unknown, Unknown", 0, 0

def categorize_threat(alert):
    """
    Categorizes alert severity based on the type of attack.
    Returns one of: "High", "Medium", or "Low".
    """
    if "SYN Flood" in alert or "Brute Force" in alert:
        return "High"
    elif "ARP Spoofing" in alert:
        return "Medium"
    elif "ICMP Ping" in alert:
        return "Low"
    else:
        return "Low"

def play_sound_alert():
    """Plays a beep sound to notify user of a detected threat."""
    winsound.Beep(1000, 500)

def log_alert(alert, ip="Unknown"):
    """
    Logs a unique alert to the file and stores it for dashboard display.
    Uses geoip, categorizes severity, and prevents repeated alerts.
    """
    unique_alert = f"{alert} from {ip}"
    if unique_alert in logged_alerts:
        return  # Skip already logged alerts

    logged_alerts.add(unique_alert)
    location, lat, lon = get_geoip_info(ip)
    severity = categorize_threat(alert)
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")

    # Write to dashboard structure
    detected_alerts.append({
        "timestamp": timestamp,
        "alert": alert,
        "ip": ip,
        "severity": severity,
        "location": location,
        "lat": lat,
        "lon": lon
    })

    # Append to local log file
    log_entry = f"{timestamp} {alert} from {ip} | Severity: {severity} | Location: {location}\n"
    with open(log_file, "a") as file:
        file.write(log_entry)

    play_sound_alert()

# -----------------------------------
# Packet Processing Logic
# -----------------------------------

def process_packet(packet):
    """
    Analyzes each sniffed packet for known attack signatures:
    - ARP Spoofing
    - SYN Flood
    - Brute Force Attempts (based on TCP PUSH/ACK)
    - ICMP Ping (low-level network activity)
    """
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        log_alert("ARP Spoofing detected", packet[scapy.ARP].psrc)

    elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == "S":
        log_alert("SYN Flood detected", packet[scapy.IP].src)

    elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags in ["PA"]:
        log_alert("Brute Force attempt detected", packet[scapy.IP].src)

    elif packet.haslayer(scapy.ICMP):
        log_alert("ICMP Ping detected", packet[scapy.IP].src)

def sniff_packets():
    """Continuously sniffs network traffic and processes each packet."""
    scapy.sniff(prn=process_packet, store=False)

# -----------------------------------
# Flask Web Dashboard
# -----------------------------------

app = Flask(__name__)

@app.route('/')
def index():
    """Renders the main dashboard HTML page."""
    return render_template("index.html")

@app.route('/alerts')
def get_alerts():
    """Returns all recorded alerts as JSON for dashboard display."""
    return jsonify(detected_alerts)

@app.route('/chart_data')
def get_chart_data():
    """Returns count of alerts by severity level for chart rendering."""
    levels = {"High": 0, "Medium": 0, "Low": 0}
    for alert in detected_alerts:
        levels[alert["severity"]] += 1
    return jsonify(levels)

@app.route('/map_data')
def get_map_data():
    """Returns geolocation data for alerts to be plotted on a map."""
    return jsonify([
        {"ip": alert["ip"], "lat": alert["lat"], "lon": alert["lon"], "alert": alert["alert"]}
        for alert in detected_alerts if alert["lat"] and alert["lon"]
    ])

@app.route('/alerts_over_time')
def alerts_over_time():
    """
    Groups alerts by minute for plotting a time series chart.
    Useful for spotting peaks in attack frequency.
    """
    time_buckets = defaultdict(int)
    for alert in detected_alerts:
        minute_str = alert["timestamp"][1:17]  # Extract up to minute
        time_buckets[minute_str] += 1

    sorted_times = sorted(time_buckets.items())
    labels = [t[0] for t in sorted_times]
    counts = [t[1] for t in sorted_times]

    return jsonify({"labels": labels, "counts": counts})

# -----------------------------------
# Start IDS and Web Server
# -----------------------------------

if __name__ == "__main__":
    # Run the packet sniffer in a background thread
    threading.Thread(target=sniff_packets, daemon=True).start()

    # Start Flask app on localhost:5000
    app.run(debug=True)
