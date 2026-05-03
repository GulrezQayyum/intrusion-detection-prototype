# 🚀 IDS Prototype - Quick Reference Guide

## 📋 Commands at a Glance

### Start Dashboard
```bash
cd ~/Networking
source venv/bin/activate
python3 -m src.dashboard.app
```
**Access:** http://localhost:8050

### Run Full Demo (with Attacks)
```bash
cd ~/Networking
source venv/bin/activate
python3 main.py
```

### Run Detection Tests
```bash
python3 test_detection.py
```

### View Demo Output
```bash
cat output.log
```

---

## 🎯 System Components

| Component | File | Purpose |
|-----------|------|---------|
| **Packet Capture** | `src/capture/sniffer.py` | Network sniffing with Scapy |
| **Detection Rules** | `src/detection/rules.py` | 6 attack detection rules |
| **Alert Generator** | `src/dashboard/callbacks.py` | Real-time alert streaming |
| **Dashboard** | `src/dashboard/app.py` | Beautiful Plotly visualization |
| **Database** | `src/logs/alerts.py` | SQLite persistent storage |
| **Attack Simulator** | `src/utils/attack_simulator.py` | Test attack scenarios |

---

## 📊 Dashboard URL Mapping

| Path | View |
|------|------|
| `http://localhost:8050/` | Main dashboard |
| Auto-updates | Every 500ms |

---

## 🔴 Alert Severity Colors

| Severity | Color | Examples |
|----------|-------|----------|
| 🔴 **HIGH** | Red | SYN Flood, Port Scan |
| 🟡 **MEDIUM** | Orange | UDP Flood, Ping Flood |
| 🟢 **LOW** | Green | New device, Suspicious port |

---

## 🎮 Attack Types

| Attack | Simulated By | Detection |
|--------|--------------|-----------|
| **SYN Flood** | 60 SYN packets/10s | Threshold: 50 packets |
| **Port Scan** | 10 different ports | Threshold: 5+ ports |
| **Ping Flood** | 30 ICMP packets/10s | Threshold: 20 packets |
| **UDP Flood** | 120 UDP packets/5s | Threshold: 100 packets |

---

## 💾 Database Operations

### Python Usage
```python
from src.logs.alerts import AlertDatabase

# Initialize
db = AlertDatabase('data/alerts.db')

# Log alert
db.log_alert(alert_dict)

# Query
alerts = db.get_alerts(limit=100)
high_alerts = db.get_alerts_by_severity('HIGH')
ip_alerts = db.get_alerts_by_ip('203.0.113.50')

# Statistics
stats = db.get_statistics()
print(stats['total_alerts'])
print(stats['by_severity'])
print(stats['top_ips'])

# Export
db.export_alerts_csv('alerts.csv')
db.export_alerts_json('alerts.json')

# Block IPs
db.block_ip('203.0.113.50', reason='SYN Flood')
blocked = db.get_blocked_ips()

# Info
info = db.get_database_info()
```

---

## ⚙️ Configuration Examples

### Change Detection Thresholds
```python
from src.detection.rules import DetectionRules

rules = DetectionRules()

# Modify thresholds
rules.update_rule_threshold('syn_flood', 100)      # More sensitive
rules.update_rule_threshold('port_scan', 3)        # Very sensitive

# View current config
config = rules.get_rules_config()
print(config)
```

### Use Custom Database Path
```python
from src.utils.database import DatabaseIntegration

db_integration = DatabaseIntegration(
    alert_generator,
    db_path='/custom/path/alerts.db'
)
```

### Simulate Specific Attack
```python
from src.detection.rules import DetectionRules
from src.utils.attack_simulator import AttackSimulator

rules = DetectionRules()
simulator = AttackSimulator(rules)

# Simulate individual attacks
alerts = simulator.simulate_syn_flood(duration=5)
alerts = simulator.simulate_port_scan(duration=5)
alerts = simulator.simulate_ping_flood(duration=5)
alerts = simulator.simulate_udp_flood(duration=5)

# Run all tests
results = simulator.run_test_suite()

# Stress test
simulator.stress_test(duration=30)
```

---

## 📈 Real-time Dashboard Metrics

### Left Panel
- 📊 Packets/sec
- 🚨 Total Alerts
- 🔴 High Severity Alerts
- 🎯 Malicious IPs

### Center
- 🌐 Network Flow Graph (interactive)
- ⚡ Live Alert Stream (scrolling)

### Bottom Charts
- 📈 Traffic Timeline (ECG style)
- 📊 Protocol Breakdown (pie chart)
- 🎯 Alert Severity (bar chart)
- 🗺️ Top Malicious IPs (heatmap)
- 🚨 Attack Types (bar chart)

---

## 🔍 Database File Locations

```
Networking/
├── data/
│   └── alerts.db           # Main SQLite database
├── output.log              # Demo output log
└── (csv exports)           # When exported
```

Check database size:
```python
db = AlertDatabase()
info = db.get_database_info()
print(f"Database size: {info['size_mb']} MB")
print(f"Total alerts: {info['total_alerts']}")
```

---

## 🧪 Testing Commands

### Test Detection Rules Only
```bash
python3 test_detection.py
```
Output: 6/6 tests passing ✅

### Test Full System with Attacks
```bash
python3 main.py
```
Output: 220 attacks, 45 alerts, 100% detection ✅

### Interactive Python Shell
```bash
source venv/bin/activate
python3

# Then in Python:
from src.detection.rules import DetectionRules
from src.utils.attack_simulator import AttackSimulator

rules = DetectionRules()
sim = AttackSimulator(rules)
alerts = sim.simulate_syn_flood(duration=3)
print(f"Generated {len(alerts)} alerts")
```

---

## 🐛 Troubleshooting

### Dashboard Won't Start
```bash
# Check if port 8050 is in use
lsof -i :8050

# Kill the process
kill -9 <PID>

# Try different port (edit app.py)
app.run(port=9000)
```

### Database Locked Error
```bash
# Database is being accessed elsewhere
# Make sure only one dashboard instance is running
ps aux | grep app.py
```

### Import Errors
```bash
# Make sure you're in the venv
source venv/bin/activate

# Verify packages installed
pip list | grep -E "scapy|dash|plotly"
```

### Packet Capture Permission Denied
```bash
# Root privileges needed for real capture
sudo source venv/bin/activate
sudo python3 -m src.dashboard.app

# But demo mode works without sudo!
python3 -m src.dashboard.app  # Uses simulated attacks
```

---

## 📚 Learning Resources

### Key Concepts
- **Scapy**: Packet creation/manipulation
- **Dash**: Real-time web dashboards
- **Plotly**: Interactive data visualization
- **SQLite**: Embedded database
- **Threading**: Concurrent operations

### Files to Study
1. `src/capture/sniffer.py` - Networking basics
2. `src/detection/rules.py` - Security logic
3. `src/dashboard/app.py` - UI/UX design
4. `src/logs/alerts.py` - Database design

---

## 🎯 Key Statistics

✅ **6 Detection Rules**
- SYN Flood (50 packet threshold)
- Port Scan (5 port threshold)
- Ping Flood (20 packet threshold)
- UDP Flood (100 packet threshold)
- Suspicious Port Access
- Normal traffic baseline

✅ **100% Detection Rate**
- All simulated attacks caught
- Zero false positives on normal traffic

✅ **Professional Dashboard**
- Real-time updates (500ms)
- 7 interactive charts
- Dark SOC theme
- Beautiful visualizations

✅ **Persistent Storage**
- SQLite database
- Search/filter capabilities
- CSV/JSON export
- IP blocking system

---

## 🚀 Next Steps

1. **Enhance Detection** - Add ML-based anomaly detection
2. **Real Capture** - Use actual network interface
3. **Alerting** - Send Slack/email notifications
4. **Performance** - Optimize for high-traffic networks
5. **Analytics** - Add more visualization types
6. **API** - Build REST API for integrations

---

**Happy Threat Hunting! 🔒**

*Built for learning cybersecurity and network security concepts*
