# 🚨 AI-Powered Network Intrusion Detection System (IDS)

A real-time **AI + rule-based Network Intrusion Detection System** built from scratch using Python.  
Captures live network packets, extracts traffic features, runs ML anomaly detection, and visualizes everything on a live dashboard.

---

## 📸 Dashboard Preview

> Live packet-rate graph with red/green per-packet classification, top-attacker panel, and sortable traffic log table.

*(Add a screenshot of your dashboard here)*

---

## 🧠 How It Works

```
Live Network Traffic
       │
       ▼
  Scapy Sniffer          ← captures raw IP packets
       │
       ▼
Feature Extractor        ← sliding-window packet rate, protocol, packet length
       │
       ▼
Detection Engine         ← Isolation Forest (ML) + 5 rule layers
       │
       ├── NORMAL  →  logged to traffic.csv
       └── ALERT   →  logged to alerts.log + shown on dashboard
                │
                ▼
         Flask Dashboard  ← live Chart.js graph, traffic table, alert panel
```

---

## ⚙️ Detection Rules

| # | Rule | Condition | Alert Type |
|---|------|-----------|------------|
| 1 | High Packet Rate | rate > 20 p/s | ⚡ DoS / Flood |
| 2 | ML Anomaly + Elevated Rate | Isolation Forest = -1 AND rate > 12 | 🤖 Anomaly Detected by ML |
| 3 | Port Scan Pattern | packet length ≤ 60B AND rate > 5 p/s | 🔍 Possible Port Scan |
| 4 | Suspicious ICMP | ICMP protocol AND length > 200B | 📡 ICMP Abuse / Tunnel |
| 5 | ML Anomaly (any rate) | Isolation Forest = -1 | ⚠️ ML Anomaly |

---

## 🗂️ Project Structure

```
Packet_Sniffer/
│
├── sniffer_final.py        # Entry point — starts packet capture
├── feature_extractor.py    # Sliding-window feature extraction per IP
├── ids_detector.py         # Isolation Forest + rule-based detection
├── app.py                  # Flask REST API (6 endpoints)
├── ids_model.pkl           # Trained Isolation Forest model
├── traffic.csv             # Live packet log (auto-generated)
├── alerts.log              # Alert log (auto-generated)
│
└── templates/
    └── index.html          # Chart.js live dashboard
```

---

## 🚀 Setup & Run

### 1. Install dependencies

```bash
pip install scapy flask pandas scikit-learn joblib
```

> **Windows:** Scapy requires [Npcap](https://npcap.com/) — install it first.

### 2. Train the model (first time only)

```bash
python model2.py
```

This generates `ids_model.pkl`.

### 3. Start the packet sniffer

```bash
python sniffer_final.py
```

> Run as **Administrator** (Windows) or `sudo` (Linux/Mac) — required for raw packet capture.

### 4. Start the Flask dashboard

```bash
python app.py
```

Open your browser at: **http://127.0.0.1:5000**

---

## 📡 Flask API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Live dashboard |
| `GET /data` | Last 50 packets with alert status |
| `GET /log` | Last 100 packets with full details |
| `GET /stats` | Total packets, alerts, normal count |
| `GET /alerts` | Last 20 alerts with descriptive messages |
| `GET /top_attackers` | Top 5 IPs by alert count |

---

## 📊 Dashboard Features

- **Live rolling graph** — packet rate per IP, updates every 2 seconds
- **Red / Green dots** — 🔴 alert packets, 🟢 normal packets per data point
- **Hover tooltip** — shows Src IP, Dst IP, Protocol, Packet Length, Rate on hover
- **Live Alerts panel** — deduplicated by IP with alert count badges
- **Traffic Log table** — sortable by any column, filterable by All / Alerts / Normal
- **Top Attacker badge** — ⚡ TOP label on highest-alert source IPs

---

## 🤖 ML Model

- **Algorithm:** Isolation Forest (unsupervised anomaly detection)
- **Features used:** `packet_rate`, `packet_length`, `protocol`
- **Training data:** 5,000+ live-captured packets
- **Why Isolation Forest:** No labelled attack data needed — learns what "normal" looks like and flags deviations

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| Packet Capture | Scapy |
| ML Model | scikit-learn (Isolation Forest) |
| Feature Engineering | Python, Pandas |
| Backend API | Flask |
| Frontend | HTML, Chart.js, CSS |
| Data Storage | CSV (traffic log), plain text (alerts) |

---

## 📝 Requirements

```
scapy
flask
pandas
scikit-learn
joblib
numpy
```

---

## 👤 Author

**Karan Shihire**  
[LinkedIn](https://www.linkedin.com/in/karan-singh-shihire-5292a5283/) • [GitHub](https://github.com/karan95427)

---

## ⭐ If you found this useful, give it a star!
