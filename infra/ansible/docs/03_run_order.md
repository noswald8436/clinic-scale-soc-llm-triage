# Run order (high level)

Recommended order:
1) `wazuh.yml` — install/validate Wazuh single-node on WAZUH01
2) `ehr_stack.yml` — deploy Postgres, FastAPI app, nginx UI/proxy
3) `llm01.yml` — install Ollama + pull model
4) `triage01.yml` — install triage tooling + systemd service + UI

Then:
- validate detections (100202/100205/100210/100211)
- validate Live AI Analyst (local + cloud mode)

