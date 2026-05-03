"""
Alert Generation and Management
Bridges packet capture with detection rules and logging
"""

from collections import deque
from datetime import datetime
import threading
import logging

logger = logging.getLogger(__name__)


class AlertGenerator:
    """
    Coordinates packet capture, detection rules, and alert logging
    Acts as the central alert management system
    """

    def __init__(self, packet_capture, detection_rules, max_alerts=500):
        """
        Initialize alert generator
        
        Args:
            packet_capture (PacketCapture): Instance of packet capture module
            detection_rules (DetectionRules): Instance of detection rules engine
            max_alerts (int): Maximum alerts to keep in memory
        """
        self.packet_capture = packet_capture
        self.detection_rules = detection_rules
        self.alerts = deque(maxlen=max_alerts)
        
        self.is_running = False
        self.analysis_thread = None
        self.lock = threading.Lock()
        
        # Statistics
        self.total_alerts_generated = 0
        self.alerts_by_severity = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        self.alerts_by_type = {}

    def start(self):
        """Start continuous packet analysis in background thread"""
        if self.is_running:
            logger.warning("Alert generator already running")
            return
        
        self.is_running = True
        self.analysis_thread = threading.Thread(
            target=self._continuous_analysis,
            daemon=True,
            name="AlertGeneratorThread"
        )
        self.analysis_thread.start()
        logger.info("Started alert generator")

    def stop(self):
        """Stop continuous analysis"""
        self.is_running = False
        if self.analysis_thread:
            self.analysis_thread.join(timeout=2)
        logger.info(f"Stopped alert generator. Total alerts: {self.total_alerts_generated}")

    def _continuous_analysis(self):
        """
        Background thread that continuously analyzes packets
        Called periodically to detect new attacks
        """
        import time
        
        last_packet_index = 0
        
        while self.is_running:
            try:
                # Get new packets since last check
                all_packets = self.packet_capture.get_packets()
                
                if len(all_packets) > last_packet_index:
                    new_packets = all_packets[last_packet_index:]
                    
                    # Analyze each new packet
                    for packet in new_packets:
                        alerts = self.detection_rules.analyze_packet(packet)
                        for alert in alerts:
                            self._process_alert(alert)
                    
                    last_packet_index = len(all_packets)
                
                # Small sleep to avoid busy-waiting
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in continuous analysis: {e}")
                time.sleep(1)

    def _process_alert(self, alert):
        """
        Process a newly generated alert
        
        Args:
            alert (dict): Alert information from detection rules
        """
        with self.lock:
            # Add metadata
            alert['id'] = len(self.alerts)
            alert['generated_at'] = datetime.now().isoformat()
            
            # Store alert
            self.alerts.append(alert)
            self.detection_rules.add_alert_to_history(alert)
            
            # Update statistics
            self.total_alerts_generated += 1
            severity = alert.get('severity', 'LOW')
            if severity in self.alerts_by_severity:
                self.alerts_by_severity[severity] += 1
            
            alert_type = alert.get('type', 'UNKNOWN')
            self.alerts_by_type[alert_type] = self.alerts_by_type.get(alert_type, 0) + 1
            
            # Log alert
            self._log_alert(alert)

    def _log_alert(self, alert):
        """Log alert with appropriate severity level"""
        severity = alert.get('severity', 'INFO')
        message = alert.get('message', 'Unknown alert')
        
        if severity == 'HIGH':
            logger.warning(f"🔴 [HIGH] {message}")
        elif severity == 'MEDIUM':
            logger.info(f"🟡 [MEDIUM] {message}")
        else:
            logger.info(f"🟢 [LOW] {message}")

    def get_recent_alerts(self, count=50):
        """
        Get most recent alerts
        
        Args:
            count (int): Number of recent alerts to return
            
        Returns:
            list: List of alert dictionaries (most recent first)
        """
        with self.lock:
            alerts_list = list(self.alerts)
            return alerts_list[-count:][::-1]  # Reverse to get most recent first

    def get_alerts_by_severity(self, severity):
        """
        Get alerts filtered by severity level
        
        Args:
            severity (str): 'HIGH', 'MEDIUM', or 'LOW'
            
        Returns:
            list: Filtered alert list
        """
        with self.lock:
            return [a for a in self.alerts if a.get('severity') == severity]

    def get_alerts_by_type(self, alert_type):
        """
        Get alerts of specific type
        
        Args:
            alert_type (str): Type of alert (e.g., 'SYN_FLOOD', 'PORT_SCAN')
            
        Returns:
            list: Filtered alert list
        """
        with self.lock:
            return [a for a in self.alerts if a.get('type') == alert_type]

    def get_alerts_for_ip(self, ip_address):
        """
        Get all alerts involving a specific IP
        
        Args:
            ip_address (str): Source IP address
            
        Returns:
            list: Alerts from this IP
        """
        with self.lock:
            return [a for a in self.alerts if a.get('src_ip') == ip_address]

    def get_alert_statistics(self):
        """
        Get comprehensive alert statistics
        
        Returns:
            dict: Alert statistics and summaries
        """
        with self.lock:
            return {
                'total_alerts': self.total_alerts_generated,
                'current_alerts': len(self.alerts),
                'by_severity': dict(self.alerts_by_severity),
                'by_type': dict(self.alerts_by_type),
                'detection_rules_stats': self.detection_rules.get_alert_statistics()
            }

    def clear_alerts(self):
        """Clear all stored alerts"""
        with self.lock:
            self.alerts.clear()
            logger.info("Alert buffer cleared")

    def export_alerts_csv(self, filename):
        """
        Export alerts to CSV file
        
        Args:
            filename (str): Path to CSV file
        """
        try:
            import csv
            
            with self.lock:
                alerts_list = list(self.alerts)
            
            if not alerts_list:
                logger.warning("No alerts to export")
                return
            
            # Get all unique keys from alerts
            fieldnames = set()
            for alert in alerts_list:
                fieldnames.update(alert.keys())
            fieldnames = sorted(list(fieldnames))
            
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(alerts_list)
            
            logger.info(f"Exported {len(alerts_list)} alerts to {filename}")
            
        except Exception as e:
            logger.error(f"Error exporting alerts to CSV: {e}")

    def get_threat_level(self):
        """
        Calculate overall threat level based on recent alerts
        
        Returns:
            str: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'SAFE'
        """
        with self.lock:
            high_alerts = self.alerts_by_severity['HIGH']
            medium_alerts = self.alerts_by_severity['MEDIUM']
            
            # Simple heuristic for threat level
            if high_alerts > 10:
                return 'CRITICAL'
            elif high_alerts > 3:
                return 'HIGH'
            elif medium_alerts > 20:
                return 'HIGH'
            elif medium_alerts > 5:
                return 'MEDIUM'
            elif len(self.alerts) > 0:
                return 'LOW'
            else:
                return 'SAFE'

    def get_top_suspicious_ips(self, top_n=10):
        """
        Get IPs with most alerts
        
        Args:
            top_n (int): Number of top IPs to return
            
        Returns:
            list: List of (ip, alert_count) tuples
        """
        from collections import defaultdict
        
        with self.lock:
            ip_counts = defaultdict(int)
            for alert in self.alerts:
                src_ip = alert.get('src_ip')
                if src_ip and src_ip != 'N/A':
                    ip_counts[src_ip] += 1
            
            return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

    def reset_statistics(self):
        """Reset all alert statistics (keep stored alerts)"""
        with self.lock:
            self.total_alerts_generated = 0
            self.alerts_by_severity = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            self.alerts_by_type = {}
            logger.info("Alert statistics reset")
