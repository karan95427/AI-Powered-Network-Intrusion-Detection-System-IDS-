from scapy.all import sniff, IP
from feature_extractor import extract_features
from ids_detector import detect
import csv
import os

# Reset files on every run
with open("traffic.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "src_ip", "dst_ip", "protocol",
        "packet_length", "packet_rate", "packet_count", "result"
    ])

open("alerts.log", "w", encoding="utf-8").close()


def packet_callback(packet):
    features = extract_features(packet)
    if features is None:
        return

    result = detect(features)
    print(features, "->", result)

    with open("traffic.csv", "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            features["src_ip"],
            features["dst_ip"],
            features["protocol"],
            features["packet_length"],
            features["packet_rate"],
            features.get("packet_count", 0),
            result          # ← save per-row result: "NORMAL" or "ALERT | ..."
        ])

    if result.startswith("ALERT"):
        with open("alerts.log", "a", encoding="utf-8") as f:
            f.write(f"{result} from {features['src_ip']}\n")


print("Sniffer running...")
sniff(prn=packet_callback, store=False)