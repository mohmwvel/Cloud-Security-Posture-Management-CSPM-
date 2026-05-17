# Cloud Security Posture Management (CSPM) Tool

## Overview
A lightweight, automated Cloud Security Posture Management (CSPM) utility designed to audit AWS environments for common security misconfigurations. This tool identifies high-risk vulnerabilities such as public data exposure and unencrypted assets, providing clear, actionable remediation paths.

## Features
- **Automated Scanning:** Evaluates S3, IAM, EC2 Security Groups, and EBS volumes.
- **Reporting Engine:** Generates color-coded PDF reports and JSON exports with timestamps.
- **Modern Dashboard:** Built with Flask, featuring a clean, responsive UI and summary statistics.
- **Mock Mode:** Included demonstration capability for testing without active AWS credentials.
- **Security-First Design:** Rate limiting, error handling, modular services, and environment variable configuration.

## Architecture
The application follows a modular MVC architecture:
- **Presentation Layer:** Flask web server with Jinja2 templates and Vanilla CSS.
- **Service Layer:** Orchestrates scanning modules and aggregates findings.
- **Scanner Layer:** Abstract base class implementation with specialized modules (S3, IAM, EC2, SG) using `boto3`.
- **Utility Layer:** Provides centralized logging and dynamic PDF/JSON generation.

## Tech Stack
- **Backend:** Python 3.9+, Flask, Boto3
- **Frontend:** HTML5, CSS3
- **Reporting:** ReportLab
- **Testing:** Pytest
- **Infrastructure:** Docker

## Installation

```bash
git clone <repository-url>
cd "new project cs"

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
```

## AWS Setup
Configure your AWS CLI to enable live environment scanning. The IAM user should have `SecurityAudit` or `ReadOnlyAccess` permissions.

```bash
aws configure
```

## Usage

### Running Locally
```bash
python run.py
```
Navigate to `http://127.0.0.1:5000`. Click **Start Live Scan** to audit your configured AWS environment, or **Run Demo Scan** to test the UI with mock data.

### Running with Docker
```bash
docker build -t cspm-tool .
docker run -p 5000:5000 cspm-tool
```

## Sample Findings
* **S3 Buckets:** Detects `AllUsers` public read/write access control lists.
* **IAM Users:** Identifies users without Multi-Factor Authentication (MFA).
* **Security Groups:** Flags `0.0.0.0/0` unrestricted access on ports 22 and 3389.
* **EBS Volumes:** Reports unencrypted data volumes.

## Project Structure
```text
cspm_tool/
├── app/
│   ├── routes.py
│   ├── scanners/
│   │   ├── base_scanner.py
│   │   ├── s3_scanner.py
│   │   └── ...
│   ├── services/
│   │   └── scanner_service.py
│   ├── templates/
│   ├── static/
│   └── utils/
├── tests/
├── .env.example
├── Dockerfile
├── requirements.txt
└── run.py
```

## Future Improvements
- Implement AWS Lambda and RDS configuration scanners.
- Add support for Azure and GCP environments.
- Integrate automated email alerts for critical findings.
