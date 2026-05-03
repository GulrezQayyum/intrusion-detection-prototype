"""
Database Integration Layer
Connects Alert Generator with Alert Database for persistent storage
"""

import threading
import logging
from datetime import datetime
from src.logs.alerts import AlertDatabase

logger = logging.getLogger(__name__)


class DatabaseIntegration:
    """
    Bridges AlertGenerator and AlertDatabase
    Automatically saves all alerts to persistent storage
    """

    def __init__(self, alert_generator, db_path='data/alerts.db'):
        """
        Initialize database integration
        
        Args:
            alert_generator (AlertGenerator): Instance of alert generator
            db_path (str): Path to SQLite database
        """
        self.alert_generator = alert_generator
        self.db = AlertDatabase(db_path)
        self.is_running = False
        self.sync_thread = None
        
        logger.info("Database integration initialized")

    def start(self):
        """Start background sync of alerts to database"""
        if self.is_running:
            logger.warning("Database sync already running")
            return
        
        self.is_running = True
        self.sync_thread = threading.Thread(
            target=self._sync_alerts_to_db,
            daemon=True,
            name="DatabaseSyncThread"
        )
        self.sync_thread.start()
        logger.info("Started database sync service")

    def stop(self):
        """Stop database sync"""
        self.is_running = False
        if self.sync_thread:
            self.sync_thread.join(timeout=2)
        logger.info("Stopped database sync service")

    def _sync_alerts_to_db(self):
        """Background thread that syncs alerts to database"""
        last_synced_count = 0
        
        while self.is_running:
            try:
                # Get current alert count
                recent_alerts = self.alert_generator.get_recent_alerts(500)
                
                # Log new alerts to database
                alerts_to_log = recent_alerts[last_synced_count:]
                
                if alerts_to_log:
                    self.db.log_multiple_alerts(alerts_to_log)
                    last_synced_count = len(recent_alerts)
                
                # Sleep for a bit
                import time
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error syncing alerts to database: {e}")
                import time
                time.sleep(2)

    def get_alert_history(self, limit=100, offset=0):
        """Get historical alerts from database"""
        return self.db.get_alerts(limit, offset)

    def get_statistics(self):
        """Get database statistics"""
        return self.db.get_statistics()

    def block_malicious_ip(self, ip_address):
        """Block an IP address"""
        self.db.block_ip(ip_address, reason='Detected suspicious activity')

    def get_blocked_ips(self):
        """Get list of blocked IPs"""
        return self.db.get_blocked_ips()

    def export_to_csv(self, filename):
        """Export alerts to CSV"""
        self.db.export_alerts_csv(filename)

    def export_to_json(self, filename):
        """Export alerts to JSON"""
        self.db.export_alerts_json(filename)

    def get_database_info(self):
        """Get database information"""
        return self.db.get_database_info()
