from scapy.all import sniff, IP, TCP, UDP
import threading
import time
import queue

class PacketSniffer:
    def __init__(self, packet_queue):
        self.packet_queue = packet_queue
        self.is_running = False
        self.captured_packets = []
        self.packet_stats = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'other': 0
        }

    def start_capture(self):
        self.is_running = True
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_capture(self):
        self.is_running = False
        if hasattr(self, 'capture_thread'):
            self.capture_thread.join(timeout=1)

    def _capture_packets(self):
        try:
            sniff(prn=self._packet_callback, store=False, 
                  stop_filter=lambda _: not self.is_running)
        except Exception as e:
            print(f"Error in packet capture: {e}")

    def _packet_callback(self, packet):
        try:
            if IP in packet:
                packet_info = {
                    'time': time.strftime('%H:%M:%S'),
                    'src': packet[IP].src,
                    'dst': packet[IP].dst,
                    'proto': 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Other',
                    'length': len(packet),
                }

                self.packet_stats['total'] += 1
                if TCP in packet:
                    self.packet_stats['tcp'] += 1
                elif UDP in packet:
                    self.packet_stats['udp'] += 1
                else:
                    self.packet_stats['other'] += 1

                self.packet_queue.put(packet_info)
                
                self.captured_packets.append(packet_info)
                if len(self.captured_packets) > 1000:
                    self.captured_packets.pop(0)

        except Exception as e:
            print(f"Error processing packet: {e}")