# VULNSecure - Hybrid Vulnerability Detection System

[![Python](https://img.shields.io/badge/Python-3.7+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.0+-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Machine Learning](https://img.shields.io/badge/Machine-Learning-FF6F00?style=for-the-badge&logo=tensorflow&logoColor=white)](https://www.tensorflow.org/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![PRs](https://img.shields.io/badge/PRs-Welcome-brightgreen?style=for-the-badge)](http://makeapullrequest.com)

> A hybrid vulnerability detection system combining rule-based scanning with machine learning risk assessment to secure modern web applications.

## Architecture

`mermaid
graph TB
    subgraph "Frontend"
        UI[React Dashboard]
        API_Client[API Client]
    end

    subgraph "Backend Services"
        Flask[Flask Server]
        Scanner[Scanner Engine]
        ML[ML Risk Analyzer]
        DarkWeb[Dark Web Monitor]
    end

    subgraph "Data Layer"
        MongoDB[(MongoDB)]
        Redis[(Redis Cache)]
        CVE_DB[(CVE Database)]
    end

    subgraph "External APIs"
        OWASP[OWASP API]
        Shodan[Shodan API]
    end

    UI --> Flask
    API_Client --> Flask
    Flask --> Scanner
    Flask --> ML
    Flask --> DarkWeb
    Scanner --> CVE_DB
    Scanner --> OWASP
    Scanner --> Shodan
    ML --> MongoDB
    DarkWeb --> MongoDB
    Flask --> Redis
`

## System Flow

`mermaid
flowchart TD
    A[User Submits Target URL] --> B{Input Validation}
    B -->|Invalid| C[Return Error]
    B -->|Valid| D[Initialize Scanner]
    D --> E[Port Scanning]
    D --> F[Service Detection]
    D --> G[Vulnerability Check]
    E --> H[Aggregate Results]
    F --> H
    G --> H
    H --> I[ML Risk Assessment]
    I --> J{Risk Level}
    J -->|Critical| K[Immediate Alert]
    J -->|High| L[Priority Report]
    J -->|Medium| M[Standard Report]
    J -->|Low| N[Info Report]
    K --> O[Generate Report]
    L --> O
    M --> O
    N --> O
    O --> P[Send Notification]
    O --> Q[Store in Database]
`

## Project Structure

`
FINALYEAR-PROJECT/
├── app.py                      # Main Flask application entry point
├── config.py                   # Configuration settings
├── requirements.txt            # Python dependencies
│
├── scanner/                    # Vulnerability scanning modules
│   ├── __init__.py
│   ├── web_scanner.py          # Web application vulnerability scanner
│   ├── network_scanner.py      # Network port & service scanner
│   ├── port_scanner.py         # TCP/UDP port scanning
│   ├── ssl_scanner.py          # SSL/TLS vulnerability detection
│   └── cve_checker.py          # CVE database lookup
│
├── ml_model/                   # Machine learning components
│   ├── __init__.py
│   ├── trainer.py              # Model training pipeline
│   ├── predictor.py            # Risk prediction engine
│   ├── feature_extractor.py    # Feature extraction from scan results
│   └── models/                 # Saved ML models
│       ├── risk_classifier.pkl
│       └── severity_model.pkl
│
├── dark_web/                   # Dark web monitoring
│   ├── __init__.py
│   ├── monitor.py              # Dark web crawler
│   ├── credential_checker.py   # Leaked credential detection
│   └── alert_system.py         # Alert notification system
│
├── reports/                    # Report generation
│   ├── __init__.py
│   ├── generator.py            # PDF/HTML report generator
│   ├── templates/              # Report templates
│   │   ├── executive_summary.html
│   │   └── technical_detail.html
│   └── exports/                # Generated reports
│
├── api/                        # REST API endpoints
│   ├── __init__.py
│   ├── routes.py               # API route definitions
│   ├── auth.py                 # Authentication endpoints
│   └── validators.py           # Input validation
│
├── templates/                  # Frontend HTML templates
│   ├── base.html
│   ├── dashboard.html
│   ├── scan_results.html
│   └── reports.html
│
├── static/                     # Static assets
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   ├── dashboard.js
│   │   └── charts.js
│   └── images/
│
├── tests/                      # Test suite
│   ├── test_scanner.py
│   ├── test_ml_model.py
│   └── test_api.py
│
├── docs/                       # Documentation
│   ├── architecture.md
│   ├── api_reference.md
│   └── deployment.md
│
├── docker/                     # Docker configuration
│   ├── Dockerfile
│   └── docker-compose.yml
│
└── scripts/                    # Utility scripts
    ├── setup.sh
    └── train_model.py
`

## Features

| Feature | Description | Status |
|---------|-------------|--------|
| Web Vulnerability Scanning | OWASP Top 10 detection | Done |
| Port Scanning | TCP/UDP port discovery | Done |
| SSL/TLS Analysis | Certificate & protocol checks | Done |
| ML Risk Assessment | AI-powered threat scoring | Done |
| Dark Web Monitoring | Credential leak detection | Done |
| Automated Reports | PDF/HTML generation | Done |
| Real-time Dashboard | Live scan monitoring | Done |
| API Integration | RESTful API endpoints | Done |

## Tech Stack

`
┌─────────────────────────────────────────────────────────┐
│                      TECH STACK                         │
├─────────────────┬─────────────────┬─────────────────────┤
│    Frontend     │     Backend     │      Database       │
├─────────────────┼─────────────────┼─────────────────────┤
│  React.js       │  Python         │  MongoDB            │
│  HTML5/CSS3     │  Flask          │  Redis              │
│  Chart.js       │  Celery         │  SQLite (dev)       │
│  Bootstrap 5    │  Gunicorn       │                     │
├─────────────────┴─────────────────┴─────────────────────┤
│                    ML & Security                        │
├─────────────────┬─────────────────┬─────────────────────┤
│  TensorFlow     │  scikit-learn   │  pandas             │
│  NumPy          │  OWASP ZAP      │  Nmap               │
│  Shodan API     │  CVE Database   │  requests           │
└─────────────────┴─────────────────┴─────────────────────┘
`

## Installation

`ash
# Clone the repository
git clone https://github.com/Jashwanth33/FINALYEAR-PROJECT.git
cd FINALYEAR-PROJECT

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys

# Initialize database
python scripts/setup.py

# Run the application
python app.py
`

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/scan | Start new vulnerability scan |
| GET | /api/v1/scan/:id | Get scan status |
| GET | /api/v1/scan/:id/results | Get scan results |
| GET | /api/v1/reports | List all reports |
| POST | /api/v1/reports/generate | Generate report |
| GET | /api/v1/dashboard/stats | Dashboard statistics |

## Usage Examples

`python
from scanner import WebScanner
from ml_model import RiskPredictor

# Initialize scanner
scanner = WebScanner(target="https://example.com")

# Run scan
results = scanner.scan()

# Get ML risk assessment
predictor = RiskPredictor()
risk_score = predictor.predict(results)

print(f"Risk Score: {risk_score}/10")
print(f"Vulnerabilities Found: {len(results)}")
`

## Contributing

1. Fork the repository
2. Create your feature branch (git checkout -b feature/AmazingFeature)
3. Commit your changes (git commit -m 'Add some AmazingFeature')
4. Push to the branch (git push origin feature/AmazingFeature)
5. Open a Pull Request

## License

Distributed under the MIT License. See LICENSE for more information.

## Author

**Jashwanth** - [GitHub](https://github.com/Jashwanth33) | [LinkedIn](https://linkedin.com/in/jashwanth)