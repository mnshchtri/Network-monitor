from scapy.all import sniff, IP
from collections import defaultdict
import time

class NetworkMonitor:
    def __init__(self):
        self.packet_counts = defaultdict(int)
        self.start_time = time.time()

    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.packet_counts[(src_ip, dst_ip)] += 1

    def run(self, duration=60):
        print(f"Starting network monitoring for {duration} seconds...")
        sniff(prn=self.packet_callback, timeout=duration)
        self.print_stats()

    def print_stats(self):
        print("\nNetwork Statistics:")
        print("-------------------")
        total_packets = sum(self.packet_counts.values())
        elapsed_time = time.time() - self.start_time
        print(f"Total packets captured: {total_packets}")
        print(f"Packets per second: {total_packets / elapsed_time:.2f}")
        print("\nTop 5 connections:")
        for (src, dst), count in sorted(self.packet_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"{src} -> {dst}: {count} packets")

if __name__ == "__main__":
    monitor = NetworkMonitor()
    monitor.run()
