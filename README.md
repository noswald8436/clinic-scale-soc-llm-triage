# Clinic-Scale SOC LLM Triage (Wazuh)

Capstone project demonstrating clinic-scale security alert triage using Wazuh and a standardized, sanitized case-bundle format. The project compares cloud vs local LLM-assisted triage and includes a Live AI Analyst web UI that triages alerts as they occur.

## Why this project
Remote/satellite clinics often operate with limited on-site IT. High-signal security and availability alerts can be triaged slowly or inconsistently when telemetry is uneven and triage is ad hoc. This project builds a repeatable workflow and measures timeliness and agreement across triage modes.

## What’s included
- **Wazuh-based monitoring** (Windows Sysmon + Security logs, Linux auth/service logs, and service-layer logs)
- **EHR-like 3-tier stack** to generate realistic clinic signals (auth failures + upstream outages)
- **Sanitized case bundles** (minimum necessary fields) to standardize triage inputs
- **Cloud LLM triage** (OpenAI API) and **local/offline LLM triage** (Ollama)
- **Live AI Analyst UI** (FastAPI + background worker) with Local/Cloud toggle and ON/OFF control
- **Auditable artifacts**: bundle/result/meta JSON outputs (excluded from git by default)

## Key results (initial)
- 3/3 classification & priority agreement across manual, cloud, and local for three controlled cases (Rules 100202/100205/100210)
- Cloud elapsed time: seconds per case; Local elapsed time: minutes per case (see `evaluation/`)

## Documentation
- Project overview: `docs/overview.md`
- Live demo runbook: `docs/runbook-live-demo.md`

## Figures
- Network architecture: `docs/figures/fig01_network_architecture.png`
- EHR request & logging flow: `docs/figures/fig02_ehr_request_logging_flow.png`
- Detection-to-triage pipeline: `docs/figures/fig03_detection_triage_pipeline.png`
- Live AI Analyst architecture: `docs/figures/fig04_live_ai_analyst_architecture.png`
- Timing comparison: `docs/figures/fig05_timing_comparison.png`
- Cloud vs local decision logic: `docs/figures/fig06_cloud_vs_local_decision_tree.png`

## Safety / data handling
- No real PHI is used; service data is synthetic.
- Any cloud triage uses sanitized bundles only (“minimum necessary” fields).
- Secrets (API keys/passwords) are not stored in this repo.
