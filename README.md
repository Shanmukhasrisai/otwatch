# 🏭 OTWatch

> Open-source passive OT/ICS security visibility & detection platform

[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)]

## What It Does

OTWatch passively monitors industrial networks (Modbus TCP), discovers
assets, detects dangerous PLC write commands, and exposes everything
through a REST API.

## How It Works

Network Traffic → Passive Capture (Scapy) → Modbus Parsing → Asset Discovery → Detection → Alerts → REST API (FastAPI)

## Features

- 🔍 Passive Modbus TCP monitoring (no active scanning — safe for production)
- 🏷️ Automatic asset discovery
- ⚠️ PLC write-command detection
- 💾 Persistent event + alert storage (SQLite)
- 🌐 REST API (FastAPI)
- 🧪 Tested Modbus parser (golden-byte tests)
- 🐳 Docker support

## Quick Start

Run these commands in three separate terminals exactly as shown:

```bash
python simulators/modbus_sim.py
sudo python -m otwatch.sniffer lo
uvicorn otwatch.api:app --port 8000
curl http://127.0.0.1:8000/api/alerts
```

Open the dashboard at http://localhost:8000 and inspect assets, events, and alerts.

## Architecture

OTWatch is intentionally simple: a passive sniffer captures Modbus TCP frames using Scapy, a protocol parser extracts events, an inventory module stores assets and events in SQLite, and an alert engine persists suspicious write operations which are exposed via a FastAPI backend and dashboard.

## Roadmap

See docs/UPGRADE_PLAN.md for the project upgrade plan (phased improvements including detection registry, behavioral baselining, and SIEM output).

## Limitations

- Currently supports Modbus TCP only
- Designed for lab/small networks; performance benchmarks pending
- No authentication or RBAC yet (on the roadmap)

## License

This project is licensed under the MIT License — see the LICENSE file for details.
