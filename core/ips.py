import time
from collections import defaultdict

class IPS:
    def _init_(self, alert_threshold=100, time_window=10):
        self.alert_threshold = alert_threshold  # Threshold for number of packets
        self.time_window = time_window  # Time window in seconds to track packets
        self.packet_count = defaultdict(list)  # Tracks packet timestamps per IP

    def analyze_packet(self, src_ip):
        now = time.time()
        # Clean up timestamps older than the time window
        self.packet_count[src_ip] = [t for t in self.packet_count[src_ip] if now - t < self.time_window]

        # Increment the packet count
        self.packet_count[src_ip].append(now)

        # Check if the count exceeds the alert threshold
        if len(self.packet_count[src_ip]) > self.alert_threshold:
            print(f"Potential attack detected from {src_ip}: {len(self.packet_count[src_ip])} packets in {self.time_window} seconds.")
            return True  # Indicates an attack
        return False  # No attack detected
