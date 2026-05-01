"""
Test script for packet capture functionality
Run with: sudo python test_sniffer.py
"""

import sys
import time
import logging
from src.capture.sniffer import PacketCapture

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_packet_capture(duration=10):
    """Test packet capture for specified duration"""
    
    print("\n" + "="*60)
    print("  PACKET CAPTURE TEST")
    print("="*60 + "\n")
    
    # Create packet capturer
    capturer = PacketCapture(packet_buffer_size=500)
    
    print(f"Starting packet capture for {duration} seconds...")
    print("(Make sure to run with sudo: sudo python test_sniffer.py)\n")
    
    # Start capture
    capturer.start()
    
    # Capture for specified duration
    try:
        for i in range(duration):
            time.sleep(1)
            stats = capturer.get_statistics()
            print(f"[{i+1}s] Packets: {stats['packet_count']:4d} | "
                  f"Rate: {stats['packets_per_sec']:6.2f} pkt/sec | "
                  f"Data: {stats['bytes_captured']/1024:.2f} KB")
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    
    # Stop capture
    capturer.stop()
    
    # Display results
    print("\n" + "="*60)
    print("  CAPTURE RESULTS")
    print("="*60 + "\n")
    
    stats = capturer.get_statistics()
    ip_stats = capturer.get_ip_statistics()
    
    print(f"Total Packets Captured: {stats['packet_count']}")
    print(f"Total Data: {stats['bytes_captured']/1024:.2f} KB")
    print(f"Average Rate: {stats['packets_per_sec']:.2f} packets/sec")
    print(f"Capture Duration: {stats['elapsed_time']:.2f} seconds\n")
    
    print("Protocol Distribution:")
    for protocol, count in stats['protocol_distribution'].items():
        percentage = (count / stats['packet_count'] * 100) if stats['packet_count'] > 0 else 0
        print(f"  {protocol}: {count} ({percentage:.1f}%)")
    
    print(f"\nTop Source IPs:")
    sorted_src = sorted(ip_stats['src_ips'].items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in sorted_src:
        print(f"  {ip}: {count} packets")
    
    print(f"\nTop Destination IPs:")
    sorted_dst = sorted(ip_stats['dst_ips'].items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in sorted_dst:
        print(f"  {ip}: {count} packets")
    
    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    test_packet_capture(duration=15)
