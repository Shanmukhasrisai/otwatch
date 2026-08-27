# 👁️ OTWatch

**Passive OT/ICS Network Monitoring Tool** — discovers PLCs & SCADA devices on industrial networks and alerts on dangerous Modbus write operations.

🛡️ **100% Passive** — zero active scanning, safe for production OT networks.

![Python](https://img.shields.io/badge/python-3.11-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20docker-lightgrey)

## ✨ Features

- 🔍 **Passive Asset Discovery** — automatically finds Modbus devices (PLCs, HMIs, SCADA) just by listening to network traffic — no risky scans
- 📡 **Modbus TCP Parsing** — decodes function codes, unit IDs, read/write operations (port 502)
- 🚨 **Real-Time Security Alerts** — instant HIGH severity alert when a WRITE operation (codes 5, 6, 15, 16) hits a PLC
- 📊 **Live Web Dashboard** — dark-mode UI showing assets, event feed & alerts (auto-refresh)
- 🔌 **REST API** — FastAPI with auto-generated docs at `/docs`
- 💾 **SQLite Storage** — asset inventory + event history
- ��� **Docker Ready** — one command deployment

## 🚀 Quick Start

```bash
git clone https://github.com/Shanmukhasrisai/otwatch.git
cd otwatch
pip install -r requirements.txt
```

### Run (3 terminals)

```bash
# Terminal 1 — start a fake PLC simulator (for testing, no hardware needed)
python simulators/modbus_sim.py

# Terminal 2 — start the passive sniffer (needs sudo for packet capture)
sudo python -m otwatch.sniffer eth0     # change eth0 to your interface (ip a)

# Terminal 3 — start the API + dashboard
uvicorn otwatch.api:app --port 8000
```

Open 👉 **http://localhost:8000** — see discovered assets, events & alerts.

### Trigger a Test Alert 🔴

```bash
python -c "
from pymodbus.client.sync import ModbusTcpClient
c = ModbusTcpClient('127.0.0.1', port=502)
c.write_register(0, 1234)   # write operation → triggers HIGH alert!
"
```

## 🐳 Docker Deployment

```bash
docker-compose up -d
```

Access the dashboard at **http://localhost:8000**

## 🖥️ Dashboard

The web dashboard displays real-time monitoring data:

| Panel | What it shows |
|-------|--------------|
| 📊 Stats Cards | Total assets, events, and alerts count |
| 🚨 Alerts | Red HIGH-severity write-operation alerts |
| 🖥️ Assets | Discovered PLCs/HMIs with live status |
| 📡 Event Feed | Live Modbus traffic (READ=blue, WRITE=red) |

Dark mode enabled for extended monitoring sessions.

## 🏗️ Architecture

```
Network Traffic ──▶ Sniffer (Scapy) ──▶ Modbus Parser
                                            │
                          ┌─────────────────┼─────────────────┐
                          ▼                 ▼                 ▼
                    Asset Inventory    Event Database    Alert Engine
                          └─────────────────┼─────────────────┘
                                            ▼
                                     FastAPI REST API
                                            ▼
                                    Web Dashboard (Live)
```

## 📂 Project Structure

```
otwatch/
├── otwatch/
│   ├── __init__.py
│   ├── api.py              # FastAPI application
│   ├── sniffer.py          # Packet capture & Modbus parsing
│   ├── inventory.py        # Asset database
│   ├── alerts.py           # Alert engine
│   └── protocols/
│       ├── __init__.py
│       └── modbus.py       # Modbus TCP protocol handler
├── simulators/
│   └── modbus_sim.py       # Test PLC simulator
├── web/
│   ├── index.html          # Dashboard UI
│   └── assets/             # CSS, JS, icons
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── LICENSE
└── README.md
```

## 🗺️ Roadmap

- [x] Modbus TCP support
- [x] Write-operation alerting
- [x] Web dashboard
- [ ] S7comm support (Siemens PLCs)
- [ ] EtherNet/IP support (Allen-Bradley)
- [ ] Rogue device detection (new device alerts)
- [ ] Traffic charts & PDF reports
- [ ] Multi-tenant MSSP edition

## 🧪 Tested With

- pymodbus simulator (fake PLC)
- Debian / Ubuntu Linux
- Docker

## ⚠️ Disclaimer

This tool is for **authorized security monitoring only**. Only use on networks you own or have written permission to monitor. Unauthorized network monitoring may violate local laws.

## 📄 License

MIT © 2025 Shanmukhasrisai

See [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📞 Support

For issues, questions, or suggestions, please [open an issue](https://github.com/Shanmukhasrisai/otwatch/issues).
