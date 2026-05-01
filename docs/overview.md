# Project Overview — Clinic-Scale SOC Alert Triage with Wazuh and Cloud vs Local LLMs

## Problem and motivation
Remote and satellite clinic locations often operate with limited on-site IT staffing while relying on centralized teams for connectivity and support. This model can create a practical security and availability risk: high-signal alerts may be triaged slowly or inconsistently when telemetry is uneven, alert context is fragmented, and analyst actions are not standardized. In clinic environments, delays can have outsized impact because credential compromise and service outages directly affect patient-facing operations and recovery timelines.

This capstone addresses that risk by designing a clinic-scale “mini SOC” reference implementation focused on two outcomes:
1) improving visibility with consistent telemetry collection and high-signal detections, and  
2) improving triage speed and repeatability through a standardized triage workflow that can be executed manually or augmented by an LLM.

## Lab setting (clinic-scale model)
The project was implemented in a segmented lab environment using Proxmox and an OPNsense firewall to emulate a clinic boundary. Two subnets are used:
- **Servers LAN (10.10.10.0/24):** core services and centralized systems  
- **Clinic LAN (10.10.20.0/24):** Windows 11 clinic workstations (shared/front desk/billing/provider/IT)

Core services include:
- **DC01:** AD DS / DNS / DHCP
- **WAZUH01 (Wazuh v4.14.5):** manager + indexer (OpenSearch) + dashboard
- **TRIAGE01:** SOC tooling host and Live AI Analyst UI
- **LLM01:** local/offline LLM host via Ollama

All endpoints are onboarded to Wazuh. Windows endpoints are instrumented with **Sysmon** and Windows Security log collection. Linux endpoints provide authentication/service telemetry.

## Why an EHR-like three-tier stack
A key goal was to evaluate triage under conditions that resemble real clinic operations. Host-only telemetry is valuable, but many clinic-impacting events appear as service-layer signals—especially authentication failures and availability disruptions. To generate realistic and repeatable triage cases, the lab includes a minimal EHR-like three-tier stack:
- **Web tier:** nginx reverse proxy (ehr.cliniclab.local)
- **App tier:** FastAPI application that emits structured JSON audit logs (login success/failure, patient list access)
- **DB tier:** PostgreSQL storing synthetic patient records

This architecture produces clinic-relevant alerts such as repeated login failures and upstream 502 errors when the app tier is unavailable.

## Detections and triage workflow
The detection and triage approach is designed to be repeatable and measurable.

### Wazuh detections (initial evaluated cases)
This capstone validated three service-layer detections used for initial evaluation:
- **Rule 100202:** single failed EHR login (login_failed)
- **Rule 100205:** brute-force correlation (repeated failures in a window)
- **Rule 100210:** nginx 502 upstream failure for login requests (availability-impacting)

### Case bundle concept (standardized inputs)
To standardize triage and reduce data-handling risk, alerts are transformed into sanitized **case bundles**. Bundles include only minimum necessary fields for triage, such as:
- rule metadata (rule_id, description, level)
- host/agent context (agent name/IP, location)
- key fields (src_ip, username, request path, reason/status)

The same bundle structure is used for manual and LLM-assisted triage to enable apples-to-apples comparison.

### Cloud vs local LLM triage modes
The workflow supports two LLM-assisted modes:
- **Cloud mode:** calls the OpenAI API using sanitized bundles only (fast turnaround; external data-handling considerations)
- **Local/offline mode:** calls Ollama on LLM01 (policy fit/offline capability; slower inference)

Both modes produce structured triage JSON with a consistent schema:
- classification (benign/suspicious/incident)
- priority (low/medium/high)
- confidence
- summary and recommended next steps

## Evaluation method and initial results
Evaluation focuses on measurable outcomes:
- **Timing:** manual mean time-to-triage (MTTT) baseline vs model elapsed time
- **Agreement:** classification and priority agreement across manual/cloud/local
- **Consistency:** repeatability of outputs and recommended next steps

Initial evaluation used three controlled scenarios (Rules 100202/100205/100210). For these three cases, classification and priority matched across manual baseline, cloud LLM, and local LLM. Timing results showed a clear operational tradeoff: cloud triage completed in single-digit seconds per case, while local/offline inference typically required one to three minutes per case. These results support a practical recommendation: use cloud triage when policy permits and rapid turnaround is required; use local/offline triage when external processing is restricted or connectivity is unreliable.

## Live AI Analyst (operational proof-of-concept)
In addition to offline evaluation, the project includes a browser-accessible **Live AI Analyst** interface on TRIAGE01. It runs as a background service that:
1) polls the Wazuh Indexer (OpenSearch) for new alerts (wazuh-alerts-*)
2) builds a sanitized mini-bundle per alert
3) performs triage in cloud or local mode (operator-controlled toggle)
4) writes auditable artifacts to disk (bundle/result/meta JSON)
5) displays latest triage + expandable history in the UI

The Live AI Analyst demonstrates real-time feasibility without automated response actions. Failures (e.g., LLM unavailable) are captured as error fields in the triage result to preserve auditability and support manual fallback.

## Safety and data handling
This project uses synthetic service data and does not handle real patient data. Any content sent to cloud LLMs is sanitized to align with HIPAA-like “minimum necessary” handling. Secrets (API keys/passwords) are provided via environment variables or local environment files and are not stored in this repository.

