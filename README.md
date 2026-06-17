# 🛡️ CyTrack – Cyber Threat Intelligence Platform

<p align="center">
  <b>Multi-Source Threat Intelligence, Correlation & Investigation Platform</b>
</p>

<p align="center">
  Built with Django, PostgreSQL, Celery, Redis, Docker, and modern threat intelligence sources.
</p>

---

## Overview

CyTrack is a Cyber Threat Intelligence (CTI) platform designed to collect, enrich, correlate, and visualize threat intelligence from multiple public sources.

The platform ingests Indicators of Compromise (IOCs), Vulnerabilities (CVEs), and Threat Intelligence feeds, then builds correlation reports to support investigations and security analysis.

---

## Features

### Threat Intelligence Sources

* AlienVault OTX Integration
* CISA Known Exploited Vulnerabilities (KEV)
* National Vulnerability Database (NVD)
* Extensible ingestion framework for additional providers

### Intelligence Processing

* IOC Normalization
* IOC Deduplication
* Threat Scoring Engine
* Risk Prioritization
* Correlation Report Generation
* Source Confidence Analysis

### Investigation Platform

* IOC Investigation APIs
* Correlation Reports
* Threat Relationship Discovery
* Vulnerability Intelligence
* Threat Actor Tracking

### Dashboard

* Interactive Threat Dashboard
* Global Threat Heatmap
* Chart.js Analytics
* Source Coverage Metrics
* Vulnerability Statistics
* Correlation Analytics

### Platform Features

* JWT Authentication
* Role-Based Access Control (RBAC)
* Organization Support
* PostgreSQL Database
* Docker Deployment
* Celery Background Tasks
* Redis Caching & Task Broker
* WebSocket Alerts

---

## Current Dataset (Development)

Current development environment contains:

* 438+ Indicators of Compromise (IOCs)
* 6,113 Vulnerabilities
* 447 Correlation Reports
* Multiple Threat Intelligence Sources

---

## Technology Stack

| Component      | Technology              |
| -------------- | ----------------------- |
| Backend        | Django 5                |
| API            | Django REST Framework   |
| Database       | PostgreSQL              |
| Authentication | JWT                     |
| Task Queue     | Celery                  |
| Cache/Broker   | Redis                   |
| WebSockets     | Django Channels         |
| Frontend       | HTML, CSS, JavaScript   |
| Charts         | Chart.js                |
| Deployment     | Docker & Docker Compose |

---

## Project Structure

```text
CyTrack/
├── apps/
│   ├── accounts/
│   ├── alerts/
│   ├── ingestion/
│   ├── intelligence/
│   └── investigation/
├── cyber/
├── dashboard/
├── docker/
├── templates/
├── static/
└── manage.py
```

## Quick Start

### Clone Repository

```bash
git clone https://github.com/Krupal1574/CyTrack.git
cd CyTrack
```

### Create Environment

```bash
python -m venv venv
venv\Scripts\activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment Variables

Create `.env`

```env
SECRET_KEY=your_secret_key
DEBUG=True

OTX_API_KEY=your_otx_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
NVD_API_KEY=your_nvd_key
```

### Run Migrations

```bash
python manage.py migrate
```

### Start Development Server

```bash
python manage.py runserver
```

---

## Roadmap

* VirusTotal Integration
* AbuseIPDB Full Integration
* Threat Actor Profiling
* Investigation UI
* IOC Search Engine
* Correlation Graph Visualization
* PDF Investigation Reports
* Multi-Tenant SaaS Deployment

---

## Author

Krupal Prajapati

GitHub: https://github.com/Krupal1574

---

## License

MIT License
