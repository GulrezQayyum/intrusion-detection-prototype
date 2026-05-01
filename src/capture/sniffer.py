"""
Packet Capture Module
Handles real-time network packet sniffing using Scapy with threading
"""

import threading
import time
from collections import deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Real-time packet sniffer using Scapy
    Captures packets in a separate thread to avoid blocking main application
    """

    def __init__(self, interface=None, packet_buffer_size=1000):
        """
        Initialize packet capture
        
        Args:
            interface (str): Network interface to sniff from (None = default)
            packet_buffer_size (int): Max packets to keep in memory
        """
        self.interface = interface
        self.packet_buffer_size = packet_buffer_size
        self.packets = deque(maxlen=packet_buffer_size)
        
        self.is_running = False
        self.capture_thread = None
        self.packet_count = 0
        self.start_time = None
        
        # Statistics
        self.bytes_captured = 0
        self.protocol_count = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        
        # Lock for thread-safe operations
        self.lock = threading.Lock()

    def start(self):
        """Start packet capture in background thread"""
        if self.is_running:
            logger.warning("Packet capture already running")
            return
        
        self.is_running = True
        self.start_time = time.time()
        self.capture_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.capture_thread.start()
        logger.info(f"Started packet capture on interface: {self.interface or 'default'}")

    def stop(self):
        """Stop packet capture"""
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        logger.info(f"Stopped packet capture. Total packets: {self.packet_count}")

    def _sniff_packets(self):
        """
        Background thread function - continuously sniffs packets
        """
        try:
            sniff(
                prn=self._process_packet,
                iface=self.interface,
                store=False,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            self.is_running = False

    def _process_packet(self, packet):
        """
        Process individual captured packet
        Extract features and store in buffer
        """
        try:
            packet_info = self._extract_packet_info(packet)
            
            with self.lock:
                self.packets.append(packet_info)
                self.packet_count += 1
                self.bytes_captured += len(packet)
                
                # Update protocol count
                protocol = packet_info['protocol']
                if protocol in self.protocol_count:
                    self.protocol_count[protocol] += 1
                else:
                    self.protocol_count['Other'] += 1
                    
        except Exception as e:
            logger.debug(f"Error processing packet: {e}")

    def _extract_packet_info(self, packet):
        """
        Extract relevant features from packet
        
        Returns:
            dict: Packet information with key features
        """
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'size': len(packet),
            'src_ip': 'N/A',
            'dst_ip': 'N/A',
            'protocol': 'Unknown',
            'src_port': None,
            'dst_port': None,
            'flags': None,
            'payload_size': 0
        }

        # Extract IP layer information
        if IP in packet:
            ip_layer = packet[IP]
            packet_info['src_ip'] = ip_layer.src
            packet_info['dst_ip'] = ip_layer.dst
            packet_info['payload_size'] = ip_layer.len

            # TCP packets
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport
                packet_info['flags'] = tcp_layer.flags
            
            # UDP packets
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = udp_layer.sport
                packet_info['dst_port'] = udp_layer.dport
            
            # ICMP packets
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'

        return packet_info

    def get_packets(self, count=None):
        """
        Get captured packets
        
        Args:
            count (int): Number of recent packets to retrieve (None = all)
        
        Returns:
            list: List of packet dictionaries
        """
        with self.lock:
            if count is None:
                return list(self.packets)
            else:
                return list(self.packets)[-count:] if count > 0 else []

    def get_statistics(self):
        """
        Get capture statistics
        
        Returns:
            dict: Capture statistics
        """
        with self.lock:
            elapsed_time = time.time() - self.start_time if self.start_time else 0
            packets_per_sec = self.packet_count / elapsed_time if elapsed_time > 0 else 0
            
            return {
                'packet_count': self.packet_count,
                'bytes_captured': self.bytes_captured,
                'packets_per_sec': round(packets_per_sec, 2),
                'elapsed_time': round(elapsed_time, 2),
                'protocol_distribution': dict(self.protocol_count),
                'is_running': self.is_running
            }

    def clear_packets(self):
        """Clear packet buffer"""
        with self.lock:
            self.packets.clear()
            logger.info("Packet buffer cleared")

    def get_ip_statistics(self):
        """
        Get statistics grouped by IP addresses
        
        Returns:
            dict: IP-based statistics
        """
        with self.lock:
            src_ips = {}
            dst_ips = {}
            
            for pkt in self.packets:
                src = pkt['src_ip']
                dst = pkt['dst_ip']
                
                if src != 'N/A':
                    src_ips[src] = src_ips.get(src, 0) + 1
                if dst != 'N/A':
                    dst_ips[dst] = dst_ips.get(dst, 0) + 1
            
            return {
                'src_ips': src_ips,
                'dst_ips': dst_ips
            }
