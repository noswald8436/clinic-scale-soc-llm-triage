# Architecture

This project is organized around three layers:

1) **Lab environment architecture** (segmented clinic model)
2) **Detection-to-triage pipeline** (alerts → bundles → LLM → results)
3) **Live AI Analyst implementation** (real-time polling + UI)

## Lab environment (segmented clinic model)
The lab is segmented into:
- **Servers LAN (10.10.10.0/24):** DC01, WAZUH01, TRIAGE01, LLM01, and EHR-like service tiers
- **Clinic LAN (10.10.20.0/24):** Windows 11 clinic workstations

Routing and segmentation are enforced by OPNsense.

**Figure:** `docs/figures/fig01_network_architecture.*`

## EHR-like application stack
A minimal three-tier “EHR-like” stack generates realistic authentication and outage signals:
- Web tier (nginx reverse proxy)
- App tier (FastAPI with structured JSON audit logs)
- DB tier (PostgreSQL with synthetic records)

**Figure:** `docs/figures/fig02_ehr_request_logging_flow.*`

## Detection-to-triage pipeline
Telemetry is ingested into Wazuh; alerts are indexed in the Wazuh Indexer (OpenSearch). TRIAGE01 polls for new alerts and creates sanitized case bundles. Those bundles are triaged using either:
- Cloud LLM (OpenAI API), or
- Local/offline LLM (Ollama)

Outputs are written as bundle/result/meta artifacts for auditability and evaluation.

**Figure:** `docs/figures/fig03_detection_triage_pipeline.*`

## Live AI Analyst (real-time workflow)
Live AI Analyst runs as a FastAPI web UI with a background polling worker (systemd). It:
- polls wazuh-alerts-* (OpenSearch :9200)
- builds sanitized mini-bundles
- runs triage (cloud/local toggle)
- writes artifacts to disk (bundle/result/meta)

**Figure:** `docs/figures/fig04_live_ai_analyst_architecture.*`
