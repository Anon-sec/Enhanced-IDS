# Intrusion Detection System (IDS)

This project is a simple Intrusion Detection System (IDS) that monitors network traffic, detects threats, logs alerts, and provides a web dashboard.

---
# ⚠️ Important Note

The logic used in this project is **not reliable** for actual intrusion detection. This Intrusion Detection System (IDS) was created solely for **educational and demonstration purposes**.

---

## ❌ Do NOT Rely on This for Real-World Security

- The detection algorithms are **oversimplified** and **not thoroughly tested**.
- The system generates a **high rate of false positives**.
- The logic is **faulty** and may **miss real threats** or **flag harmless traffic** as malicious.

---

Use this project to **understand how an IDS works**, not as a dependable tool for network defense.

---

## 🔐 Features

- Detects ARP spoofing, SYN floods, brute force attacks, and port scans  
- Logs alerts with timestamps and geolocation data  
- Provides a web-based dashboard with threat severity charts  
- Includes a test script (`test_ids.py`) to verify IDS functionality

---

## 📁 Folder Structure

```
Intrusion_Detection/
│── ids.py                    # Main IDS script
│── ids_log.txt               # Log file for detected threats
│── requirements.txt          # Dependencies
│
├── templates/                # HTML templates
│   └── index.html            # Dashboard UI
│
├── static/                   # Static files
│   ├── css/
│   │   └── style.css         # Styling for dashboard
│   └── js/
│       └── chart.js          # JavaScript for charts
│
└── README.md                 # Documentation
```

---

## ⚙️ Installation

1. **Install Dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the IDS**  
   ```bash
   python ids.py
   ```

3. **Open the Web Dashboard**  
   Visit: [http://localhost:5000](http://localhost:5000)

---

## 🧪 How to Test IDS Functionality

### 1. Run the Test Script

After starting `ids.py`, open another terminal and run:
```bash
python test_ids.py
```

This will test:

- GeoIP lookup  
- ARP spoofing detection  
- SYN flood detection  
- Brute force attack detection  
- Web dashboard accessibility  
- Log file validation

---

### 2. Check IDS Logs

- Open `ids_log.txt` to verify detected threats.  
- Check the web dashboard at [http://localhost:5000](http://localhost:5000) to see if alerts appear.

---

> Developed as part of **Project 2** for **PG**.
