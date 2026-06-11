# VULNSecure - Hybrid Vulnerability Detection System

[![Python](https://img.shields.io/badge/Python-3.7+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.0+-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Machine Learning](https://img.shields.io/badge/Machine-Learning-FF6F00?style=for-the-badge&logo=tensorflow&logoColor=white)](https://www.tensorflow.org/)

## Overview

VULNSecure is a hybrid vulnerability detection system designed to secure modern web applications. It combines rule-based scanning with machine learning risk assessment to reduce false positives, prioritize threats, and automate reporting.

## Features

- **Hybrid Detection Engine** - Combines rule-based and ML-based detection
- **Dark Web Monitoring** - Identifies leaked credentials and sensitive data
- **Risk Assessment** - ML-powered threat prioritization
- **Automated Reporting** - Generate comprehensive security reports
- **False Positive Reduction** - Smart filtering to minimize noise

## Architecture

`
┌─────────────────────────────────────────────┐
│              VULNSecure System              │
├─────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │  Scanner  │  │ ML Model │  │ Dark Web │ │
│  │  Engine   │  │ Analyzer │  │ Monitor  │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘ │
│       │              │              │       │
│       └──────────────┼──────────────┘       │
│                      │                      │
│              ┌───────┴───────┐              │
│              │   Reporting   │              │
│              │    Module     │              │
│              └───────────────┘              │
└─────────────────────────────────────────────┘
`

## Tech Stack

- **Backend:** Python, Flask
- **ML/AI:** scikit-learn, TensorFlow, pandas
- **Security:** OWASP rules, CVE database
- **Database:** MongoDB
- **Frontend:** React.js (dashboard)

## Installation

`ash
# Clone the repository
git clone https://github.com/Jashwanth33/FINALYEAR-PROJECT.git

# Navigate to project directory
cd FINALYEAR-PROJECT

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
`

## Usage

1. Start the server: python app.py
2. Access the dashboard at http://localhost:5000
3. Enter target URL to scan
4. View vulnerability reports and risk assessments

## Project Structure

`
FINALYEAR-PROJECT/
├── app.py                 # Main application entry
├── scanner/               # Vulnerability scanning modules
│   ├── __init__.py
│   ├── web_scanner.py     # Web vulnerability scanner
│   └── network_scanner.py # Network vulnerability scanner
├── ml_model/              # Machine learning models
│   ├── __init__.py
│   ├── trainer.py         # Model training
│   └── predictor.py       # Risk prediction
├── dark_web/              # Dark web monitoring
├── reports/               # Report generation
├── templates/             # HTML templates
├── static/                # Static assets
├── requirements.txt       # Dependencies
└── README.md              # This file
`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (git checkout -b feature/AmazingFeature)
3. Commit your changes (git commit -m 'Add some AmazingFeature')
4. Push to the branch (git push origin feature/AmazingFeature)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Jashwanth** - [GitHub](https://github.com/Jashwanth33)