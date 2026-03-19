from flask import Flask, render_template, jsonify
import pandas as pd
import os

app = Flask(__name__)

ALERT_ICONS = {
    "High Packet Rate":       "⚡",
    "Anomaly Detected by ML": "🤖",
    "Possible Port Scan":     "🔍",
    "Suspicious ICMP":        "📡",
    "ML Anomaly":             "⚠️",
}


def add_icon(msg):
    for key, icon in ALERT_ICONS.items():
        if key in msg:
            return f"{icon} {msg}"
    return msg


def parse_alerts():
    entries = []
    if not os.path.exists("alerts.log"):
        return entries
    with open("alerts.log", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if " from " in line:
                parts = line.rsplit(" from ", 1)
                msg = parts[0].strip()
                ip  = parts[1].strip()
            else:
                msg = line
                ip  = "unknown"
            entries.append({"msg": msg, "ip": ip})
    return entries


def load_csv():
    if not os.path.exists("traffic.csv"):
        return None
    df = pd.read_csv("traffic.csv", encoding="utf-8")
    # Ensure result column exists (backwards compat with old CSVs)
    if "result" not in df.columns:
        df["result"] = "NORMAL"
    return df


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/data")
def get_data():
    df = load_csv()
    if df is None:
        return jsonify([])

    data = []
    for _, row in df.tail(50).iterrows():
        result   = str(row.get("result", "NORMAL"))
        is_alert = result.startswith("ALERT")
        data.append({
            "packet_rate":   row["packet_rate"],
            "packet_length": row["packet_length"],
            "packet_count":  int(row.get("packet_count", 0)),
            "src":           row["src_ip"],
            "dst":           row["dst_ip"],
            "protocol":      int(row["protocol"]),
            "is_alert":      is_alert          # ← per-packet, not per-IP
        })

    return jsonify(data)


@app.route("/log")
def get_log():
    df = load_csv()
    if df is None:
        return jsonify([])

    rows = []
    for _, row in df.tail(100).iterrows():
        result   = str(row.get("result", "NORMAL"))
        is_alert = result.startswith("ALERT")
        rows.append({
            "src":           row["src_ip"],
            "dst":           row["dst_ip"],
            "protocol":      int(row["protocol"]),
            "packet_length": int(row["packet_length"]),
            "packet_rate":   round(float(row["packet_rate"]), 4),
            "packet_count":  int(row.get("packet_count", 0)),
            "result":        "ALERT" if is_alert else "NORMAL"
        })

    rows.reverse()
    return jsonify(rows)


@app.route("/stats")
def stats():
    df = load_csv()
    if df is None:
        return jsonify({})

    total_packets = len(df)
    total_alerts  = 0
    if os.path.exists("alerts.log"):
        with open("alerts.log", encoding="utf-8") as f:
            total_alerts = sum(1 for line in f if line.strip())

    return jsonify({
        "total_packets": total_packets,
        "alerts":        total_alerts,
        "normal":        total_packets - total_alerts
    })


@app.route("/alerts")
def get_alerts():
    entries = parse_alerts()
    recent  = entries[-20:]
    recent.reverse()
    return jsonify([f"{add_icon(e['msg'])} — {e['ip']}" for e in recent])


@app.route("/top_attackers")
def top_attackers():
    entries = parse_alerts()
    counts  = {}
    for e in entries:
        counts[e["ip"]] = counts.get(e["ip"], 0) + 1
    sorted_ips = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return jsonify(sorted_ips[:5])


if __name__ == "__main__":
    app.run(debug=True)