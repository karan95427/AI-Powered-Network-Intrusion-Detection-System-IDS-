import joblib
import numpy as np
import pandas as pd

model = joblib.load("ids_model.pkl")

PROTO_MAP = {6: "TCP", 17: "UDP", 1: "ICMP"}


def detect(features):
    try:
        data = pd.DataFrame([{
            "protocol":      features["protocol"],
            "packet_length": features["packet_length"],
            "packet_rate":   features["packet_rate"]
        }])

        prediction = model.predict(data)

        proto      = features["protocol"]
        rate       = features["packet_rate"]
        pkt_len    = features["packet_length"]
        proto_name = PROTO_MAP.get(proto, f"Proto-{proto}")

        # Rule 1: Very high packet rate -> flood / DoS
        if rate > 20:
            return f"ALERT | High Packet Rate ({proto_name}, {rate} p/s)"

        # Rule 2: ML anomaly + elevated rate
        if prediction[0] == -1 and rate > 12:
            return f"ALERT | Anomaly Detected by ML ({proto_name}, {rate} p/s)"

        # Rule 3: Many small packets -> likely port scan
        if pkt_len <= 60 and rate > 5:
            return f"ALERT | Possible Port Scan ({proto_name}, len={pkt_len}B)"

        # Rule 4: Large ICMP -> ping flood / ICMP tunnel
        if proto == 1 and pkt_len > 200:
            return f"ALERT | Suspicious ICMP (len={pkt_len}B)"

        # Rule 5: ML anomaly at any rate (lower confidence)
        if prediction[0] == -1:
            return f"ALERT | ML Anomaly ({proto_name}, {rate} p/s)"

        return "NORMAL"

    except Exception as e:
        print("Detection error:", e)
        return "ERROR"