"""
Attack Simulator
Generates simulated malicious traffic for testing IDS detection
Useful for demonstrations and validation without needing real attacks
"""

import random
import time
from datetime import datetime
import threading
import logging

logger = logging.getLogger(__name__)


class AttackSimulator:
    """
    Simulates different types of network attacks
    Injects simulated packets into the detection engine
    """

    def __init__(self, detection_rules, num_workers=3):
        """
        Initialize attack simulator
        
        Args:
            detection_rules (DetectionRules): Detection engine instance
            num_workers (int): Number of parallel simulation threads
        """
        self.detection_rules = detection_rules
        self.num_workers = num_workers
        self.is_running = False
        self.worker_threads = []
        self.generated_alerts = []
        self.lock = threading.Lock()

    def create_test_packet(self, src_ip, dst_ip, protocol, src_port=None, 
                          dst_port=None, flags=None):
        """Helper to create test packet"""
        return {
            'timestamp': datetime.now().isoformat(),
            'size': random.randint(40, 1500),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'flags': flags,
            'payload_size': random.randint(0, 1460)
        }

    def simulate_syn_flood(self, attacker_ip='203.0.113.100', target_ip='192.0.2.1',
                          duration=10, packet_rate=10):
        """
        Simulate SYN flood attack
        
        Args:
            attacker_ip (str): Source IP of attacker
            target_ip (str): Target IP being attacked
            duration (int): Duration in seconds
            packet_rate (int): Packets per second
        """
        logger.info(f"🚨 Simulating SYN Flood: {attacker_ip} -> {target_ip}")
        
        alerts = []
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            for _ in range(packet_rate):
                packet = self.create_test_packet(
                    src_ip=attacker_ip,
                    dst_ip=target_ip,
                    protocol='TCP',
                    src_port=random.randint(49152, 65535),
                    dst_port=80,
                    flags='S'
                )
                
                result = self.detection_rules.analyze_packet(packet)
                if result:
                    alerts.extend(result)
                packet_count += 1
            
            time.sleep(1 / packet_rate)
        
        logger.info(f"✅ SYN Flood Complete: {packet_count} packets, {len(alerts)} alerts")
        return alerts

    def simulate_port_scan(self, attacker_ip='198.51.100.50', target_ip='192.0.2.1',
                          ports=None, duration=5):
        """
        Simulate port scanning attack
        
        Args:
            attacker_ip (str): Scanning source IP
            target_ip (str): Target IP
            ports (list): Ports to scan (default: common ports)
            duration (int): Duration in seconds
        """
        if ports is None:
            ports = [22, 80, 443, 3306, 5432, 8080, 8443, 9000, 9200, 27017, 5984, 6379]
        
        logger.info(f"🚨 Simulating Port Scan: {attacker_ip} -> {target_ip}")
        
        alerts = []
        port_index = 0
        
        for _ in range(duration):
            packet = self.create_test_packet(
                src_ip=attacker_ip,
                dst_ip=target_ip,
                protocol='TCP',
                src_port=random.randint(49152, 65535),
                dst_port=ports[port_index % len(ports)],
                flags='S'
            )
            
            result = self.detection_rules.analyze_packet(packet)
            if result:
                alerts.extend(result)
            
            port_index += 1
            time.sleep(1)
        
        logger.info(f"✅ Port Scan Complete: {len(ports)} ports scanned, {len(alerts)} alerts")
        return alerts

    def simulate_ping_flood(self, attacker_ip='192.0.2.200', target_ip='192.0.2.1',
                           duration=10, packet_rate=5):
        """
        Simulate ICMP ping flood
        
        Args:
            attacker_ip (str): Attacker IP
            target_ip (str): Target IP
            duration (int): Duration in seconds
            packet_rate (int): Ping packets per second
        """
        logger.info(f"🚨 Simulating Ping Flood: {attacker_ip} -> {target_ip}")
        
        alerts = []
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            for _ in range(packet_rate):
                packet = self.create_test_packet(
                    src_ip=attacker_ip,
                    dst_ip=target_ip,
                    protocol='ICMP'
                )
                
                result = self.detection_rules.analyze_packet(packet)
                if result:
                    alerts.extend(result)
                packet_count += 1
            
            time.sleep(1 / packet_rate)
        
        logger.info(f"✅ Ping Flood Complete: {packet_count} packets, {len(alerts)} alerts")
        return alerts

    def simulate_udp_flood(self, attacker_ip='192.0.2.150', target_ip='192.0.2.1',
                          target_port=53, duration=10, packet_rate=20):
        """
        Simulate UDP flood attack
        
        Args:
            attacker_ip (str): Attacker IP
            target_ip (str): Target IP
            target_port (int): Target UDP port
            duration (int): Duration in seconds
            packet_rate (int): Packets per second
        """
        logger.info(f"🚨 Simulating UDP Flood: {attacker_ip} -> {target_ip}:{target_port}")
        
        alerts = []
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            for _ in range(packet_rate):
                packet = self.create_test_packet(
                    src_ip=attacker_ip,
                    dst_ip=target_ip,
                    protocol='UDP',
                    src_port=random.randint(49152, 65535),
                    dst_port=target_port
                )
                
                result = self.detection_rules.analyze_packet(packet)
                if result:
                    alerts.extend(result)
                packet_count += 1
            
            time.sleep(1 / packet_rate)
        
        logger.info(f"✅ UDP Flood Complete: {packet_count} packets, {len(alerts)} alerts")
        return alerts

    def simulate_normal_traffic(self, num_packets=20, duration=5):
        """
        Simulate normal, legitimate traffic (baseline)
        
        Args:
            num_packets (int): Number of packets to generate
            duration (int): Spread over this many seconds
        """
        logger.info(f"🟢 Simulating Normal Traffic: {num_packets} packets")
        
        alerts = []
        normal_ips = ['192.168.1.100', '192.168.1.101', '192.168.1.102']
        normal_ports = [80, 443, 8080]
        
        for i in range(num_packets):
            packet = self.create_test_packet(
                src_ip=random.choice(normal_ips),
                dst_ip='8.8.8.8',
                protocol=random.choice(['TCP', 'UDP']),
                src_port=random.randint(49152, 65535),
                dst_port=random.choice(normal_ports),
                flags='A' if random.random() > 0.5 else None
            )
            
            result = self.detection_rules.analyze_packet(packet)
            if result:
                alerts.extend(result)
            
            time.sleep(duration / num_packets)
        
        logger.info(f"✅ Normal Traffic Complete: {num_packets} packets, {len(alerts)} false alerts")
        return alerts

    def simulate_multi_vector_attack(self):
        """
        Simulate coordinated multi-vector attack
        Multiple attack types from different IPs
        """
        logger.info("🚨🚨🚨 SIMULATING MULTI-VECTOR ATTACK 🚨🚨🚨")
        
        all_alerts = []
        
        # Attack from multiple IPs simultaneously (simulated sequentially)
        attacks = [
            (self.simulate_syn_flood(duration=5, packet_rate=15), "SYN Flood"),
            (self.simulate_port_scan(duration=5), "Port Scan"),
            (self.simulate_ping_flood(duration=5, packet_rate=8), "Ping Flood"),
            (self.simulate_udp_flood(duration=5, packet_rate=30), "UDP Flood"),
        ]
        
        for alerts, attack_name in attacks:
            all_alerts.extend(alerts)
            logger.info(f"{attack_name}: {len(alerts)} alerts generated")
        
        logger.info(f"\n✅ Multi-Vector Attack Complete: {len(all_alerts)} total alerts\n")
        return all_alerts

    def run_test_suite(self):
        """
        Run complete test suite of all attack types
        """
        logger.info("\n" + "="*70)
        logger.info("🧪 RUNNING COMPLETE ATTACK SIMULATION TEST SUITE")
        logger.info("="*70 + "\n")
        
        results = {
            'syn_flood': self.simulate_syn_flood(duration=5),
            'port_scan': self.simulate_port_scan(duration=5),
            'ping_flood': self.simulate_ping_flood(duration=5),
            'udp_flood': self.simulate_udp_flood(duration=5),
            'normal_traffic': self.simulate_normal_traffic(num_packets=15),
        }
        
        # Summary
        logger.info("\n" + "="*70)
        logger.info("📊 TEST SUITE SUMMARY")
        logger.info("="*70)
        
        total_alerts = sum(len(v) for v in results.values())
        false_alerts = len(results['normal_traffic'])
        
        for test_name, alerts in results.items():
            status = "✅" if test_name != 'normal_traffic' or len(alerts) == 0 else "⚠️"
            logger.info(f"{status} {test_name:.<30} {len(alerts)} alerts")
        
        logger.info(f"\nTotal Alerts: {total_alerts}")
        logger.info(f"False Positives (normal traffic): {false_alerts}")
        logger.info(f"Detection Accuracy: {'✅ EXCELLENT' if false_alerts == 0 else '⚠️ NEEDS TUNING'}")
        logger.info("="*70 + "\n")
        
        return results

    def stress_test(self, duration=30):
        """
        Stress test: continuous random attacks
        
        Args:
            duration (int): Duration in seconds
        """
        logger.info(f"🔥 STRESS TEST: Running for {duration} seconds")
        
        attack_types = [
            self.simulate_syn_flood,
            self.simulate_port_scan,
            self.simulate_ping_flood,
            self.simulate_udp_flood,
        ]
        
        alerts_per_second = []
        start_time = time.time()
        last_alert_count = 0
        
        while time.time() - start_time < duration:
            # Randomly choose an attack
            attack = random.choice(attack_types)
            attack(duration=1)
            
            # Track alerts per second
            current_alerts = len(self.generated_alerts)
            alerts_per_second.append(current_alerts - last_alert_count)
            last_alert_count = current_alerts
        
        avg_alerts_per_sec = sum(alerts_per_second) / len(alerts_per_second) if alerts_per_second else 0
        logger.info(f"\n✅ Stress Test Complete")
        logger.info(f"Total Alerts Generated: {last_alert_count}")
        logger.info(f"Average Alerts/sec: {avg_alerts_per_sec:.1f}")
        logger.info(f"Peak Alerts/sec: {max(alerts_per_second) if alerts_per_second else 0}")

if __name__ == '__main__':
    # This would be run with the detection engine
    from src.detection.rules import DetectionRules
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    rules = DetectionRules()
    simulator = AttackSimulator(rules)
    simulator.run_test_suite()
