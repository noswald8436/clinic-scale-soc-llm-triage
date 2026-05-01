# Detections

This project uses a curated set of clinic-relevant detections to support repeatable alert triage. The set includes:
- **Service-layer detections** from an EHR-like three-tier stack (web/app/db), and
- **Endpoint detections** from Windows (Sysmon + Security) and Linux (auth/system logs).

## Status legend
- **Validated + evaluated:** Implemented and used in the initial cloud vs local LLM comparison.
- **Implemented / planned for expanded evaluation:** Included in the detection set and supported by telemetry collection; intended for additional scenario execution and evaluation.

---

## Service-layer (EHR-like stack) detections (Validated + evaluated)

### 1) EHRAPP — Single failed login (Rule ID: 100202)
**Purpose:** Detect a single failed login attempt against the EHR-like application.  
**Why it matters (clinic context):** Shared workstations and routine password mistakes are common, but repeated failures can indicate early credential guessing.  
**Typical fields for triage:** `src_ip`, `username`, request path, failure reason.  
**Expected triage outcome:** Usually **suspicious / medium** unless correlated or other context indicates broader compromise.

### 2) EHRAPP — Brute force correlation (Rule ID: 100205)
**Purpose:** Escalate repeated failed logins within a defined time window to highlight likely brute force or sustained credential guessing.  
**Why it matters:** Correlation improves prioritization by elevating patterns over one-off failures.  
**Typical logic:** Multiple failed logins (e.g., 5 within 5 minutes) associated with the same service/user/source.  
**Expected triage outcome:** Typically **incident / high** due to probable attack behavior and need for containment steps.

### 3) EHRWEB — Upstream/app outage surfaced as HTTP 502 (Rule ID: 100210)
**Purpose:** Detect availability-impacting upstream failures where nginx returns HTTP 502 for login requests (app tier unreachable/refusing connections).  
**Why it matters:** Availability is clinic-critical; outage signals require rapid scoping and restoration.  
**Typical fields for triage:** request path, HTTP status 502, web/app tier host context.  
**Expected triage outcome:** Typically **incident / high** due to immediate operational impact.

---

## Windows endpoint detections (Sysmon + Windows Security logs)
(Implemented / planned for expanded evaluation)

### 4) Windows authentication anomaly patterns (failed logons and “success after failures”)
**Purpose:** Detect bursts of failed logons and suspicious authentication sequences such as a success following repeated failures.  
**Why it matters:** Signals password spraying, brute force, or compromised credentials on clinic endpoints.  
**Primary telemetry:** Windows Security logon events (failed/success), account and logon type context.  
**Typical triage steps:** Validate source, user, logon type, workstation, time pattern; check for lateral movement indicators.

### 5) Suspicious PowerShell execution patterns (non-malicious simulation)
**Purpose:** Detect PowerShell execution consistent with common attacker tradecraft (e.g., encoded commands, suspicious flags).  
**Why it matters:** PowerShell is frequently used for reconnaissance and execution; early detection can reduce dwell time.  
**Primary telemetry:** Sysmon process creation (command line, parent process, hashes), optional PowerShell Operational logs.  
**Typical triage steps:** Review command line, parent chain, user context; validate whether activity is administrative/expected.

### 6) Persistence indicators via scheduled tasks and service creation
**Purpose:** Detect persistence mechanisms such as scheduled task creation and new/modified services.  
**Why it matters:** Persistence is a common step after initial access and is high-signal for compromise.  
**Primary telemetry:** Windows task/service creation events + Sysmon process context.  
**Typical triage steps:** Identify creator account, binary path, command line, signing/hashes; verify change approval.

### 7) Privilege escalation indicators via account and group changes
**Purpose:** Detect local account creation and privileged group membership changes (e.g., addition to local Administrators).  
**Why it matters:** Unauthorized privilege changes can quickly turn a suspicious event into an incident requiring containment.  
**Primary telemetry:** Windows Security group/account management events (plus Sysmon context if applicable).  
**Typical triage steps:** Verify change source and authorization; scope affected hosts; consider account disablement and password resets.

---

## Linux server detections (auth/syslog/journald)
(Implemented / planned for expanded evaluation)

### 8) SSH brute-force behavior
**Purpose:** Detect bursts of failed SSH authentication attempts consistent with brute force.  
**Why it matters:** Linux utility and application servers are common targets; brute force may precede compromise.  
**Primary telemetry:** `/var/log/auth.log` (or journald) failed SSH attempts; source IP and username attempts.  
**Typical triage steps:** Identify source IPs, targeted accounts, success-after-failure patterns; consider blocking/rate limiting.

### 9) Linux privilege escalation indicators (sudo-capable user creation / sudo usage)
**Purpose:** Detect privilege changes such as creation of sudo-capable users (or sudo-group membership changes) and suspicious sudo usage.  
**Why it matters:** Privilege escalation on servers is a key escalation path and high-impact indicator.  
**Primary telemetry:** auth logs/journald entries for sudo and account/group modification.  
**Typical triage steps:** Validate account provenance, review recent privileged commands, verify integrity of key configs and services.

---

## Notes on evaluation scope
The initial LLM triage comparison in this capstone focuses on the three service-layer EHR detections (100202/100205/100210) to ensure repeatability and clear scenario expectations. The Windows and Linux endpoint detections are included in the detection set and supported by telemetry collection and are intended for expanded scenario execution and evaluation as future work.
