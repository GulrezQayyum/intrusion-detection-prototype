"""
Test Detection Engine
Demonstrates all detection rules with simulated malicious traffic patterns
"""

from src.detection.rules import DetectionRules
from datetime import datetime, timedelta


def create_test_packet(src_ip, dst_ip, protocol, src_port=None, dst_port=None, flags=None):
    """Helper to create test packet"""
    return {
        'timestamp': datetime.now().isoformat(),
        'size': 64,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'src_port': src_port,
        'dst_port': dst_port,
        'flags': flags,
        'payload_size': 40
    }


def test_syn_flood():
    """Test SYN flood detection"""
    print("\n=== Testing SYN FLOOD Detection ===")
    
    rules = DetectionRules()
    
    # Simulate SYN flood from attacker IP
    attacker_ip = '192.168.1.100'
    target_ip = '10.0.0.5'
    
    alerts = []
    for i in range(60):  # Send 60 SYN packets
        packet = create_test_packet(
            src_ip=attacker_ip,
            dst_ip=target_ip,
            protocol='TCP',
            src_port=random_port(),
            dst_port=80,
            flags='S'  # SYN flag
        )
        result = rules.analyze_packet(packet)
        if result:
            alerts.extend(result)
    
    if alerts:
        print(f"✅ SYN FLOOD DETECTED: {alerts[-1]['message']}")
        print(f"   Threshold: {alerts[-1]['threshold']} | Detected: {alerts[-1]['detected_value']}")
    else:
        print("❌ SYN FLOOD NOT DETECTED")
    
    return len(alerts) > 0


def test_port_scan():
    """Test port scan detection"""
    print("\n=== Testing PORT SCAN Detection ===")
    
    rules = DetectionRules()
    
    # Simulate port scan from attacker IP
    attacker_ip = '192.168.1.105'
    target_ip = '10.0.0.5'
    
    alerts = []
    ports_to_scan = [22, 80, 443, 3306, 5432, 8080, 8443, 9000, 9200, 27017]
    
    for port in ports_to_scan:  # Scan different ports
        packet = create_test_packet(
            src_ip=attacker_ip,
            dst_ip=target_ip,
            protocol='TCP',
            src_port=random_port(),
            dst_port=port,
            flags='S'
        )
        result = rules.analyze_packet(packet)
        if result:
            alerts.extend(result)
    
    if alerts:
        print(f"✅ PORT SCAN DETECTED: {alerts[-1]['message']}")
        print(f"   Ports: {alerts[-1]['ports_scanned']}")
    else:
        print("❌ PORT SCAN NOT DETECTED")
    
    return len(alerts) > 0


def test_ping_flood():
    """Test ping flood detection"""
    print("\n=== Testing PING FLOOD Detection ===")
    
    rules = DetectionRules()
    
    # Simulate ping flood from attacker IP
    attacker_ip = '192.168.1.110'
    target_ip = '10.0.0.5'
    
    alerts = []
    for i in range(30):  # Send 30 ICMP packets
        packet = create_test_packet(
            src_ip=attacker_ip,
            dst_ip=target_ip,
            protocol='ICMP'
        )
        result = rules.analyze_packet(packet)
        if result:
            alerts.extend(result)
    
    if alerts:
        print(f"✅ PING FLOOD DETECTED: {alerts[-1]['message']}")
        print(f"   Threshold: {alerts[-1]['threshold']} | Detected: {alerts[-1]['detected_value']}")
    else:
        print("❌ PING FLOOD NOT DETECTED")
    
    return len(alerts) > 0


def test_udp_flood():
    """Test UDP flood detection"""
    print("\n=== Testing UDP FLOOD Detection ===")
    
    rules = DetectionRules()
    
    # Simulate UDP flood from attacker IP
    attacker_ip = '192.168.1.115'
    target_ip = '10.0.0.5'
    
    alerts = []
    for i in range(120):  # Send 120 UDP packets
        packet = create_test_packet(
            src_ip=attacker_ip,
            dst_ip=target_ip,
            protocol='UDP',
            src_port=random_port(),
            dst_port=53  # DNS port
        )
        result = rules.analyze_packet(packet)
        if result:
            alerts.extend(result)
    
    if alerts:
        print(f"✅ UDP FLOOD DETECTED: {alerts[-1]['message']}")
        print(f"   Threshold: {alerts[-1]['threshold']} | Detected: {alerts[-1]['detected_value']}")
    else:
        print("❌ UDP FLOOD NOT DETECTED")
    
    return len(alerts) > 0


def test_suspicious_port():
    """Test suspicious port detection"""
    print("\n=== Testing SUSPICIOUS PORT Detection ===")
    
    rules = DetectionRules()
    
    # Try to connect to suspicious ports
    attacker_ip = '192.168.1.120'
    target_ip = '10.0.0.5'
    suspicious_ports = [23, 3389, 445]  # Telnet, RDP, SMB
    
    alerts = []
    for port in suspicious_ports:
        packet = create_test_packet(
            src_ip=attacker_ip,
            dst_ip=target_ip,
            protocol='TCP',
            src_port=random_port(),
            dst_port=port,
            flags='S'
        )
        result = rules.analyze_packet(packet)
        if result:
            alerts.extend(result)
    
    if alerts:
        print(f"✅ SUSPICIOUS PORT DETECTED: {alerts[-1]['message']}")
    else:
        print("❌ SUSPICIOUS PORT NOT DETECTED")
    
    return len(alerts) > 0


def test_normal_traffic():
    """Test that normal traffic doesn't trigger alerts"""
    print("\n=== Testing NORMAL TRAFFIC (should be safe) ===")
    
    rules = DetectionRules()
    
    # Normal web traffic
    packets = [
        create_test_packet('192.168.1.1', '8.8.8.8', 'TCP', 12345, 443, 'A'),
        create_test_packet('192.168.1.1', '8.8.8.8', 'TCP', 12346, 80, 'A'),
        create_test_packet('192.168.1.1', '1.1.1.1', 'UDP', 12347, 53, None),
    ]
    
    alerts = []
    for packet in packets:
        result = rules.analyze_packet(packet)
        if result:
            alerts.extend(result)
    
    if not alerts:
        print("✅ NORMAL TRAFFIC: No false alerts generated")
    else:
        print(f"❌ FALSE ALERT: {alerts}")
    
    return len(alerts) == 0


def random_port():
    """Generate random ephemeral port"""
    import random
    return random.randint(49152, 65535)


def run_all_tests():
    """Run all detection tests"""
    print("\n" + "="*60)
    print("IDS DETECTION ENGINE TEST SUITE")
    print("="*60)
    
    results = {
        'SYN Flood': test_syn_flood(),
        'Port Scan': test_port_scan(),
        'Ping Flood': test_ping_flood(),
        'UDP Flood': test_udp_flood(),
        'Suspicious Ports': test_suspicious_port(),
        'Normal Traffic': test_normal_traffic(),
    }
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, passed_flag in results.items():
        status = "✅ PASS" if passed_flag else "❌ FAIL"
        print(f"{test_name:.<40} {status}")
    
    print("="*60)
    print(f"TOTAL: {passed}/{total} tests passed")
    print("="*60)
    
    return passed == total


if __name__ == '__main__':
    success = run_all_tests()
    exit(0 if success else 1)
