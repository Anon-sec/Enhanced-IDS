import time
import requests
from scapy.all import *

# 🌍 Test GeoIP Lookup
def test_geoip_lookup():
    try:
        response = requests.get("http://ip-api.com/json/8.8.8.8").json()
        print("[PASS] GeoIP lookup successful.") if "city" in response else print("[FAIL] GeoIP lookup failed.")
    except Exception as e:
        print(f"[FAIL] GeoIP error: {e}")

# 📡 Simulate ARP Spoofing
def test_arp_spoof_detection():
    send(ARP(op=2, psrc="192.168.1.1", hwsrc="00:11:22:33:44:55"), verbose=False)
    print("[INFO] ARP spoof test sent.")

# 🌊 Simulate SYN Flood Attack
def test_syn_flood():
    send(IP(dst="127.0.0.1") / TCP(dport=80, flags="S"), count=10, verbose=False)
    print("[INFO] SYN flood test sent.")

# 🔑 Simulate Brute Force Attack
def test_brute_force_attempt():
    send(IP(dst="127.0.0.1") / TCP(dport=22, flags="PA"), count=5, verbose=False)
    print("[INFO] Brute force test sent.")

# 🌐 Test Web Dashboard
def test_web_dashboard():
    try:
        response = requests.get("http://localhost:5000")
        print("[PASS] Web dashboard is accessible.") if response.status_code == 200 else print("[FAIL] Web dashboard failed.")
    except Exception as e:
        print(f"[FAIL] Web dashboard error: {e}")

# 📜 Check if Alerts are Logged
def test_alert_log():
    time.sleep(3)
    try:
        with open("ids_log.txt", "r") as log:
            print("[PASS] Alerts logged.") if log.readlines() else print("[FAIL] No alerts found.")
    except Exception as e:
        print(f"[FAIL] Log file error: {e}")

# 🔄 Run All Tests
if __name__ == "__main__":
    test_geoip_lookup()
    test_arp_spoof_detection()
    test_syn_flood()
    test_brute_force_attempt()
    test_web_dashboard()
    test_alert_log()
