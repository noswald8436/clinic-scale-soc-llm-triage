# Detections (Quick Reference Table)

**Status key:**  
- **Validated + evaluated** = used in initial LLM triage comparison  
- **Planned expanded evaluation** = included in detection set; intended for additional scenario runs

| # | Detection | Rule ID | Primary telemetry | Why it matters (clinic context) | Status |
|---:|---|---:|---|---|---|
| 1 | EHRAPP single failed login | 100202 | FastAPI JSON audit log | Early signal of credential guessing vs user error | Validated + evaluated |
| 2 | EHRAPP brute-force correlation | 100205 | Correlation of repeated 100202 | Elevates repeated failures to incident-likely | Validated + evaluated |
| 3 | EHRWEB nginx 502 upstream outage | 100210 | nginx access/error logs | Availability-impacting outage indicator | Validated + evaluated |
| 4 | Windows auth anomaly patterns | — | Windows Security logon events | Password spraying/brute force/compromise patterns | Planned expanded evaluation |
| 5 | Suspicious PowerShell execution | — | Sysmon process creation (+ optional PS logs) | Common attacker tradecraft; supports rapid scoping | Planned expanded evaluation |
| 6 | Persistence via scheduled tasks/services | — | Windows Security + Sysmon | Persistence indicators after access | Planned expanded evaluation |
| 7 | Privilege escalation via group/account changes | — | Windows Security account/group mgmt | High-impact unauthorized privilege changes | Planned expanded evaluation |
| 8 | Linux SSH brute-force behavior | — | Linux auth.log / journald | Common external/internal brute force signal | Planned expanded evaluation |
| 9 | Linux privilege escalation (sudo/user changes) | — | Linux auth.log / journald | Privileged activity indicating compromise | Planned expanded evaluation |

**Note:** The initial evaluation dataset focuses on detections 1–3 to ensure repeatability and clear scenario expectations. Detections 4–9 are included for continued scenario expansion.
