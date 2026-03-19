from scapy.layers.inet import IP
import time
from collections import defaultdict, deque

WINDOW_SECONDS = 10  # packets per 10 seconds
packet_timestamps = defaultdict(deque)


def extract_features(packet):
    try:
        if not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_length = len(packet)

        current_time = time.time()

        packet_timestamps[src_ip].append(current_time)

        # Evict timestamps outside the 10s window
        while (packet_timestamps[src_ip] and
               current_time - packet_timestamps[src_ip][0] > WINDOW_SECONDS):
            packet_timestamps[src_ip].popleft()

        packet_count = len(packet_timestamps[src_ip])
        packet_rate  = round(packet_count / WINDOW_SECONDS, 4)

        return {
            "src_ip":        src_ip,
            "dst_ip":        dst_ip,
            "protocol":      protocol,
            "packet_length": packet_length,
            "packet_rate":   packet_rate,
            "packet_count":  packet_count   # raw count in last 10 s
        }

    except Exception as e:
        print("Extractor error:", e)
        return None