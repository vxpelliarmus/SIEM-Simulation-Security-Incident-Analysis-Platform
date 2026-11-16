# SOC-SIM Detection Engineering Methodology

This document outlines the detection engineering principles, threshold evaluation algorithms, correlation mechanisms, and false-positive mitigation strategies implemented within SOC-SIM.

---

## 1. Detection Philosophy

Effective threat detection requires balancing sensitivity (identifying legitimate malicious activity) with specificity (minimizing false-positive noise that leads to analyst fatigue). 

SOC-SIM implements a dual-tier approach:
1. **Atomic & Threshold Rules**: Evaluates single events or sliding-window aggregations against predefined behavioral thresholds.
2. **Correlation Logic**: Evaluates multi-event state machines across temporal windows to identify compound attacks (e.g. brute force followed by successful authentication).

---

## 2. Detection Rule Catalog

| Rule ID | Rule Name | MITRE Technique | Tactic | Threshold / Window | Default Severity |
|---|---|---|---|---|---|
| `RULE-001` | SSH Brute Force Attack | `T1110` | Credential Access | ≥5 failed attempts in 120s | High |
| `RULE-002` | Successful Login Post-Failures | `T1110.001` | Initial Access | ≥3 failures + 1 success in 300s | Critical |
| `RULE-003` | Multiple Account Probing | `T1078` | Defense Evasion | ≥3 distinct accounts in 180s | Medium |
| `RULE-004` | Network Port Scanning | `T1046` | Discovery | ≥5 distinct ports in 60s | Medium |
| `RULE-005` | Sudo Privilege Abuse | `T1548.003` | Privilege Escalation | Atomic match on shell/denied | High |
| `RULE-006` | Sensitive File Modification | `T1565.001` | Impact / Persistence | Atomic match on protected path | Critical |
| `RULE-007` | Suspicious Process / Shell | `T1059.004` | Execution | Atomic match on reverse shell | High |

---

## 3. Sliding-Window Threshold Evaluation

Rather than relying on fixed bucket intervals (which can miss attacks split across boundary minutes), SOC-SIM implements a **sliding-window algorithm**:

```python
# Sliding window evaluation (from detection/engine.py)
window_start_idx = 0
for i in range(len(events)):
    current_time = parse_ts(events[i]["timestamp"])
    while (current_time - parse_ts(events[window_start_idx]["timestamp"])).total_seconds() > window_seconds:
        window_start_idx += 1
    
    events_in_window = events[window_start_idx : i + 1]
    if len(events_in_window) >= threshold:
        generate_alert(events_in_window)
        break
```

This ensures that any burst of attempts meeting the threshold within any rolling span of $N$ seconds triggers an alert, regardless of boundary alignment.

---

## 4. Multi-Event Correlation Logic

Single events in isolation often appear ambiguous. For instance:
- A single failed login is routine.
- A single successful login is normal.
- **Correlation**: When a successful login event from IP $X$ is preceded by $\ge 3$ failed login attempts from IP $X$ within a 5-minute sliding window, the severity elevates to **Critical** (`RULE-002`), indicating password guessing success or credential compromise.

### Kill-Chain Correlation
The `EventCorrelator` also tracks broad campaign progression across multiple phases:
1. **Reconnaissance**: Network port scan (`T1046`).
2. **Initial Access**: Repeated SSH authentication attempts (`T1110`).
3. **Privilege Escalation**: Unauthorized `sudo` invocation (`T1548.003`).
4. **Impact / Persistence**: Modification of `/etc/shadow` (`T1565.001`).
5. **Execution**: Reverse socket connection (`T1059.004`).

When stages spanning multiple categories are detected on the same target host, an integrated incident case dossier is automatically compiled.

---

## 5. False Positive Mitigation

A primary testing requirement of SOC-SIM is that normal baseline background telemetry (routine cron jobs, benign web traffic, authorized sudo commands such as `systemctl status`, normal SSH logins) must produce **zero false positives**.

Mitigation strategies:
- **Baseline Exclusion**: Routine administrative commands are explicitly modeled in baseline profiles.
- **Strict Filtering**: Rules verify event categories, action types, and specific anomalous arguments before flagging.
- **Sliding Window Deduplication**: If an alert has already fired for a specific rule and source IP/host within a 1-hour window, duplicate alerts are suppressed to prevent alert flooding.

---

## 6. Python Engine vs. Sigma Rules

- **Python Detection Engine (`detection/engine.py`)**: The active runtime engine responsible for parsing records from SQLite, evaluating sliding windows, enforcing stateful logic, and writing alerts to the database.
- **Sigma Rules (`sigma_rules/`)**: Standardized, YAML-based detection specifications written in Sigma format. While the simulation platform uses its lightweight Python engine for execution without third-party dependencies, the Sigma rules demonstrate detection engineering best practices and ensure interoperability with tools like `pySigma`, Splunk, or Elastic.
