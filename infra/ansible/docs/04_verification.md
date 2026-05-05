# Verification checklist

## WAZUH01
- Manager running:
  - `sudo systemctl status wazuh-manager`
- Dashboard reachable:
  - `https://<wazuh_ip>/`
- Custom rules load cleanly:
  - `sudo /var/ossec/bin/wazuh-analysisd -t`

## EHR stack
- Web UI loads:
  - `http://ehr.cliniclab.local/`
- Health endpoint:
  - `http://ehr.cliniclab.local/api/health`
- App audit logs:
  - `/var/log/ehrapp/app.log` on LNX-APP-01
- Nginx access logs:
  - `ehr_access.log` on LNX-WEB-01

## TRIAGE01
- Live AI Analyst service:
  - `sudo systemctl status live-ai-analyst`
- UI loads:
  - `http://triage.cliniclab.local/`

## LLM01
- Ollama running:
  - `curl http://<llm_ip>:11434/api/tags`
- Model present:
  - `mistral:7b-instruct` (or configured model)

## Detection validation (Discover)
- Rule 100202: EHRAPP login_failed
- Rule 100205: brute-force correlation
- Rule 100210: nginx 502 upstream failure
- Rule 100211: patients_denied
