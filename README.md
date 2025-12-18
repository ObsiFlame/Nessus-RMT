# Nessus RMT (Report Management & Tracking) - STAGE [ALPHA]
A Flask-based Vulnerability Management & Reporting Tool that connects to Tenable Nessus using API keys and provides scan visibility, risk-based vulnerability prioritization, and professional DOCX/CSV report generation.

## Purpose
This tool acts as a read-only intelligence and reporting layer on top of Nessus, designed for SOC teams, penetration testers, security consultants, and GRC teams.

## Features
- 🔐 Secure login using Nessus AccessKey & SecretKey
- 📊 Browse all Nessus scans and scan status
- 🐞 View all vulnerabilities (severity-based)
- 🎯 View prioritized vulnerabilities using:
    - VPR Score
    - CVSS v2 / v3
    - EPSS (where available)
- 📄 Generate professional DOCX vulnerability reports

## Installation & Setup
- Clone the Repository
    ```
    git clone https://github.com/<your-username>/nessus-rmt.git
    cd nessus-rmt
    ```
- Create Virtual Environment
    ```
    python -m venv venv
    source venv/bin/activate      # Linux / macOS
    venv\Scripts\activate         # Windows
    ```
- Installation of Dependencies
    ```
    pip install -r requirements.txt
    ```
- Configure Nessus URL (Edit config.py):
    ```
    NESSUS_URL = "https://<nessus-ip>:8834"
    ```
- Running the application and accessing
```
> python app.py
http://127.0.0.1:5000
```
## Security Notes
- SSL verification is disabled (intended for internal Nessus deployments)
- No write / delete operations on Nessus
- API keys are session-scoped
- Recommended to run behind VPN or internal network


