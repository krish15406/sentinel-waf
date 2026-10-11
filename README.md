
# SENTINEL WAF
### Python-Based Web Application Firewall

## 1. Project Overview

SENTINEL WAF is a Python-based Web Application Firewall prototype designed to inspect incoming HTTP requests, identify suspicious patterns, block detected threats, and record security events.

It provides a local demonstration environment for understanding web application security, threat detection, security logging, and incident reporting.

## 2. Objectives

- Inspect incoming HTTP requests.
- Detect SQL Injection patterns.
- Detect Cross-Site Scripting (XSS) patterns.
- Block requests matching configured detection rules.
- Store security events in a CSV log file.
- Display security statistics through a dashboard.
- Generate incident reports for blocked requests.

## 3. Technologies Used

- Python
- Flask
- Streamlit
- Pandas
- Regular Expressions
- CSV File Handling
- HTML/HTTP concepts

## 4. Main Features

### Request Inspection
Examines incoming requests using configured detection patterns.

### SQL Injection Detection
Identifies selected SQL Injection patterns in request data.

### XSS Detection
Identifies selected script-related patterns in request data.

### Request Blocking
Returns HTTP 403 Forbidden when a request matches a configured attack pattern.

### Security Logging
Stores request timestamps, HTTP methods, paths, IP addresses, statuses, attack types, and actions in `waf_logs.csv`.

### Security Dashboard
Displays request statistics, attack categories, and recent security events using Streamlit.

### Incident Reporting
Generates `incident_report.csv` containing recorded blocked requests.

## 5. System Architecture

Client Request
      |
      v
Flask Web Application
      |
      v
SENTINEL WAF Inspection Engine
      |
      v
Pattern-Based Threat Detection
      |
      +---- Suspicious Request ----> HTTP 403 Block
      |
      +---- Normal Request --------> Allow
      |
      v
CSV Security Logging
      |
      +----> Streamlit Dashboard
      |
      +----> Incident Report Generator

## 6. Project Files

- `app.py` — Flask application and request filtering.
- `waf_engine.py` — Threat detection rules and inspection logic.
- `dashboard.py` — Streamlit security dashboard.
- `generate_report.py` — Incident report generation.
- `waf_logs.csv` — Persistent request logs.
- `incident_report.csv` — Report of blocked requests.
- `.venv/` — Python virtual environment.

## 7. Installation and Execution

### Step 1: Open the project folder

```bash
cd ~/Desktop/waf-project
```

### Step 2: Activate the virtual environment

```bash
source .venv/bin/activate
```

### Step 3: Start the WAF application

```bash
python app.py
```

The local Flask application runs at:

`http://127.0.0.1:5001`

### Step 4: Start the dashboard

Open another terminal and run:

```bash
cd ~/Desktop/waf-project
source .venv/bin/activate
streamlit run dashboard.py
```

Open the local URL displayed by Streamlit, usually:

`http://localhost:8501`

### Step 5: Generate an incident report

After recording requests, run:

```bash
python generate_report.py
```

## 8. Testing and Results

The prototype was tested with local HTTP requests.

| Test | Expected Result | Observed Result |
|---|---|---|
| Normal request to `/` | Allow | HTTP 200 |
| SQL Injection test pattern | Block | HTTP 403 |
| XSS test pattern | Block | HTTP 403 |
| Security log generation | Save request details | Successful |
| Incident report generation | Export blocked requests | Successful |

The recorded report contained two blocked requests: one SQL Injection detection and one XSS detection.

## 9. Limitations

- Detection relies on configured regular-expression patterns.
- The prototype does not detect every possible attack.
- It is designed for local demonstration, not production deployment.
- Logs are stored in a local CSV file.
- It does not replace a professionally tested WAF or secure application design.

## 10. Future Enhancements

- Add more detection rules.
- Support JSON and structured application logs.
- Add severity levels and alert notifications.
- Introduce filtering and date-based analytics.
- Add authentication and access control.
- Improve automated testing and detection accuracy.
- Integrate with a database and external monitoring tools.

## 11. Conclusion

SENTINEL WAF demonstrates the basic principles of web application firewalls through request inspection, pattern-based threat detection, request blocking, persistent security logging, dashboard visualization, and incident report generation.

It provides a foundation for further learning in Python programming and web application security.
