# Windows endpoint notes (documented steps)

Windows nodes are documented rather than automated due to licensing/endpoint variability.

Minimum steps:
1) Join domain (optional for lab realism)
2) Install Wazuh agent and enroll with manager
3) Install Sysmon with a standard config
4) Ensure event channels are collected:
   - Security
   - Microsoft-Windows-Sysmon/Operational
5) Validate in Wazuh:
   - Sysmon Event ID 1 appears in `wazuh-alerts-*`

Recommended evidence:
- Wazuh Agents page showing endpoints connected
- Discover screenshot showing Sysmon process creation telemetry
