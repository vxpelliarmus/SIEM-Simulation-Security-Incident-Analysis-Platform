# SOC-SIM — SIEM Simulation & Security Incident Analysis Platform

[![Python](https://img.shields.io/badge/Python-3.13%2B-blue.svg?style=flat&logo=python)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40%2B-FF4B4B.svg?style=flat&logo=streamlit)](https://streamlit.io/)
[![Database](https://img.shields.io/badge/Database-SQLite3%20WAL-003B57.svg?style=flat&logo=sqlite)](https://www.sqlite.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red.svg?style=flat)](https://attack.mitre.org/)
[![Tests](https://img.shields.io/badge/Tests-30%2F30%20Passing-brightgreen.svg?style=flat)]()

> **Educational Project Disclosure:**  
> **SOC-SIM** is an educational simulation platform built to demonstrate security event generation, log collection, schema normalization, rule-based threat detection, event correlation, and incident investigation. All events and IP addresses are synthetic (using RFC 5737 and RFC 1918 reserved documentation ranges). No real external attacks are executed, and this is not a production replacement for enterprise SIEMs like Wazuh, Splunk, or Microsoft Sentinel.

---

##  Project Overview

**SOC-SIM** provides a complete, locally runnable SIEM simulation environment that demonstrates how modern Security Operations Centers (SOCs) collect, analyze, correlate, detect, investigate, and report on security threats.

The project demonstrates:
1. **Realistic Security Event Simulation**: 6 distinct cyber threat scenarios + benign background telemetry noise.
2. **Log Collection & Normalization Pipeline**: Ingestion of raw JSON logs, timestamp normalization to ISO-8601 UTC, sanitization, and duplicate ingestion prevention.
3. **Rule-Based Threat Detection Engine**: Configurable thresholds via YAML, sliding-window evaluation, and suppression of duplicate alerts.
4. **Multi-Event Correlation**: Detection of multi-stage attack patterns (e.g. brute force followed by successful authentication, and full kill-chain progression).
5. **Sigma Rules & MITRE ATT&CK Mapping**: Standardized Sigma-compatible detection rules and technique tagging across Enterprise ATT&CK tactics.
6. **SOC Analyst Dashboard**: A Streamlit dark-themed monitoring interface with live SQLite metrics, Plotly timeseries charts, event explorer, alert triage, and investigation dossier.
7. **Automated Incident Reporting**: Generation of structured Markdown incident reports adhering to NIST/SANS incident handling guidelines.

---

## Architecture

```
                                  SOC-SIM Pipeline
                                  
  ┌─────────────────────────────────┐
  │     Security Event Generator    │
  │  (SSH, Recon, Sudo, Files, Proc)│
  └────────────────┬────────────────┘
                   │ Raw JSON Logs
                   ▼
  ┌─────────────────────────────────┐
  │   Ingestion & Normalization     │  ───► Archives raw logs in data/raw/
  │  (Schema Validate, ISO-8601 UTC)│
  └────────────────┬────────────────┘
                   │ Normalized Records
                   ▼
  ┌─────────────────────────────────┐
  │      SQLite Database Store      │  ◄───► Deduplication & WAL Mode
  │   (events, alerts, notes, inc)  │
  └───────────┬───────────────┬─────┘
              │               │
     Queries  │               │ Events
              ▼               ▼
  ┌─────────────────┐   ┌─────────────────────────────────┐
  │  SOC Dashboard  │   │   Detection & Correlation       │
  │   (Streamlit)   │   │  (Sliding Window, YAML Rules)   │
  └────────┬────────┘   └────────────────┬────────────────┘
           │                             │
           │                             ▼
           │                    Generated Alerts
           │                             │
           └─────────────────────────────┘
```

Detailed architecture diagrams and flow descriptions are available in [`docs/architecture.md`](docs/architecture.md).

---

##  Technology Stack

| Component | Technology | Rationale |
|---|---|---|
| **Language** | Python 3.10+ | Standard scripting & analysis language for security automation |
| **User Interface** | Streamlit | Rapid, responsive web dashboard with dark SOC styling |
| **Visualization** | Plotly & Pandas | High-performance timeseries charts and interactive tables |
| **Database** | SQLite3 (WAL mode) | Zero-configuration local relational database, no server required |
| **Configuration** | PyYAML | Human-readable detection rules and threshold configurations |
| **Standards** | MITRE ATT&CK & Sigma | Industry-standard threat categorization and rule specification |
| **Testing** | Pytest | Automated verification of positive, negative, and correlation cases |

---

##  Repository Structure

```
SOC-SIM/
├── README.md                           # Comprehensive documentation & walkthrough
├── requirements.txt                    # Project dependencies
├── .gitignore                          # Virtualenv and cache exclusions
│
├── config/
│   └── detection_config.yaml           # Detection thresholds and window settings
│
├── simulator/                          # Telemetry simulation layer
│   ├── __init__.py
│   ├── event_generator.py              # Master generator & baseline telemetry
│   ├── ssh_simulator.py                # SSH brute force (T1110)
│   ├── login_simulator.py              # Account probing & spraying (T1078)
│   ├── network_simulator.py            # Network port scanning (T1046)
│   └── system_simulator.py             # Sudo abuse, file tampering, reverse shells
│
├── ingestion/                          # Log processing layer
│   ├── __init__.py
│   ├── normalizer.py                   # Timestamp normalization & schema validation
│   └── log_collector.py                # JSON ingestion, raw archiving, deduplication
│
├── detection/                          # Analytics & detection engine
│   ├── __init__.py
│   ├── engine.py                       # Sliding-window detection engine
│   ├── correlation.py                  # Compound multi-event correlation
│   └── rules/                          # Platform YAML detection rules
│       ├── ssh_bruteforce.yml
│       ├── suspicious_login.yml
│       ├── port_scan.yml
│       ├── privilege_escalation.yml
│       ├── file_modification.yml
│       └── suspicious_process.yml
│
├── sigma_rules/                        # Sigma-compatible standardized rules
│   ├── ssh_bruteforce.yml
│   ├── suspicious_login_failed_success.yml
│   ├── port_scan_recon.yml
│   ├── priv_esc_sudo_abuse.yml
│   ├── sensitive_file_tampering.yml
│   └── suspicious_process_reverse_shell.yml
│
├── database/                           # Persistence layer
│   ├── __init__.py
│   ├── db_manager.py                   # SQLite connection, schema, queries
│   └── soc_sim.db                      # Local SQLite database
│
├── dashboard/                          # SOC Analyst Interface
│   └── app.py                          # Multi-page Streamlit application
│
├── incident_reports/                   # Case dossiers & report generator
│   ├── __init__.py
│   ├── report_generator.py             # Automated Markdown report generator
│   ├── INC-001.md                      # SSH Brute Force investigation report
│   ├── INC-002.md                      # Network Reconnaissance report
│   └── INC-003.md                      # Privilege Escalation & File Tampering report
│
├── tests/                              # Automated validation suite (30 tests)
│   ├── __init__.py
│   ├── test_simulator.py
│   ├── test_ingestion.py
│   ├── test_detection.py
│   ├── test_database.py
│   └── test_reports.py
│
├── data/                               # Data storage directories
│   ├── raw/                            # Archived original raw JSON files
│   ├── normalized/                     # Processed logs
│   └── alerts/                         # Alert snapshots
│
└── docs/                               # Detailed documentation
    ├── architecture.md                 # Deep-dive architecture and data flow
    ├── detection_methodology.md        # Detection rules, sliding windows, and math
    └── limitations.md                  # Scope, scalability, and synthetic boundaries
```

---

##  Simulation Scenarios & MITRE ATT&CK Mapping

| Scenario | Objective | MITRE ATT&CK | Tactic | Detection Rule | Severity |
|---|---|---|---|---|---|
| **1. SSH Brute Force** | Rapid failed SSH logins from single IP | [`T1110`](https://attack.mitre.org/techniques/T1110/) | Credential Access | `RULE-001` | High |
| **2. Compromised Credential** | Successful authentication post-failures | [`T1110.001`](https://attack.mitre.org/techniques/T1110/001/) | Initial Access | `RULE-002` | Critical |
| **3. Account Probing** | Single IP cycling through multiple accounts | [`T1078`](https://attack.mitre.org/techniques/T1078/) | Defense Evasion | `RULE-003` | Medium |
| **4. Network Port Scanning** | Sequential TCP SYN scan across service ports | [`T1046`](https://attack.mitre.org/techniques/T1046/) | Discovery | `RULE-004` | Medium |
| **5. Privilege Escalation** | Unauthorized sudo attempt or root shell spawn | [`T1548.003`](https://attack.mitre.org/techniques/T1548/003/) | Privilege Escalation | `RULE-005` | High |
| **6. File Modification** | Tampering with `/etc/shadow` or `/etc/passwd` | [`T1565.001`](https://attack.mitre.org/techniques/T1565/001/) | Impact / Persistence | `RULE-006` | Critical |
| **7. Suspicious Process** | Reverse shell socket execution (`/dev/tcp/`) | [`T1059.004`](https://attack.mitre.org/techniques/T1059/004/) | Execution | `RULE-007` | High |
| **8. Benign Baseline** | Normal web requests, cron jobs, authorized sudo | N/A | Normal Operations | N/A (0 alerts) | Clean |

---

##  Installation & Execution

### Prerequisites
- Linux (tested on Kali Linux / Ubuntu 22.04+) or macOS
- Python 3.10 or higher
- Git

### 1. Setup Virtual Environment
```bash
# Clone the repository (or navigate to project directory)
cd SIEM

# Create and activate Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Launch the SOC Dashboard
```bash
# Start Streamlit application
streamlit run dashboard/app.py
```
Open your web browser and navigate to: **`http://localhost:8501`**

---

##  Dashboard Walkthrough

The dashboard provides six dedicated operational pages:

1. ** SOC Overview**:
   - Executive metric cards displaying total events, total alerts, and counts by severity.
   - Plotly interactive line chart displaying real-time events ingested per minute.
   - Donut charts breakdown for severity and bar charts for scenario distributions.
2. ** Event Explorer**:
   - Multi-field filterable grid (Category, Scenario, Result, Free-text keyword search).
   - Side-by-side inspect modal comparing normalized event structures with original raw JSON payloads.
3. ** Alert Center**:
   - Severity-colored alert triage table.
   - Detailed inspection card with supporting log evidence table.
   - Interactive status dropdown (`New`, `In Progress`, `Closed - True Positive`, `Closed - False Positive`) updating SQLite dynamically.
4. ** Threat Intelligence & MITRE**:
   - Curated reference mapping linking detection rules, tactics, and techniques to MITRE ATT&CK.
   - Tactical coverage visualization chart.
5. ** Incident Investigation**:
   - Reconstructs chronological kill-chain timelines from supporting log IDs.
   - Collaborative analyst notes section (persists analyst observations to SQLite).
   - **One-click Incident Report Generation**: Compiles formal Markdown incident reports with instant preview and download.
6. ** Simulation Control**:
   - Trigger specific attack scenarios or baseline benign noise with custom event multipliers.
   - Full end-to-end pipeline execution with live visual feedback.
   - One-click database reset and purge utility.

---

##  Testing & Validation

The project includes an automated test suite with **30 comprehensive tests** covering positive detections, negative detections (verifying that normal background traffic generates zero false positives), threshold validation, schema enforcement, SQLite operations, and report generation.

To run the complete test suite:
```bash
pytest -v tests/
```

### Test Coverage Summary
- `test_simulator.py`: Schema validation, scenario event generation, RFC documentation IP compliance.
- `test_ingestion.py`: Diverse timestamp parsing (ISO, epoch, syslog), malformed field handling, deduplication.
- `test_detection.py`: Threshold boundaries, single-event negative cases, baseline noise zero-alert verification, sliding-window deduplication.
- `test_database.py`: Table schema initialization, CRUD operations, analyst notes, and metrics calculation.
- `test_reports.py`: Markdown report compilation, breach outcome accuracy verification, and file writing.

---

##  End-to-End Workflow Demonstration

To demonstrate a complete security incident workflow:
1. Navigate to ** Simulation Control**.
2. Select **`SSH Brute Force + Compromise (T1110.001)`** and click **`Execute Simulation Pipeline`**.
3. Telemetry is generated, normalized, and stored in SQLite. The detection engine detects the dictionary attack, and the correlator triggers `RULE-002` (Critical severity).
4. Navigate to ** Alert Center** to review the triggered alert and supporting log IDs.
5. Navigate to ** Incident Investigation**, select the alert, review the chronological timeline, add an analyst note, and click **`Generate & Preview Incident Report`**.
6. The complete report is generated, saved to `incident_reports/`, and ready for download.

---

##  License & Acknowledgments

- Built for cybersecurity education, detection engineering practice, and portfolio demonstration.
- Inspired by enterprise SOC workflows and detection engineering frameworks.
