# Clinic-Scale SOC LLM Triage (Wazuh)

Capstone project demonstrating clinic-scale security alert triage using **Wazuh** and standardized **sanitized case bundles**. The project compares **cloud vs local/offline LLM triage** and includes a **Live AI Analyst** web UI that triages alerts as they occur.

**Start here:** **[docs/START_HERE.md](docs/START_HERE.md)**

---

## Quick links
- Documentation hub: **[docs/](docs/)**
- Repo start page: **[docs/START_HERE.md](docs/START_HERE.md)**
- Project overview: **[docs/overview.md](docs/overview.md)**
- Live demo runbook: **[docs/runbook-live-demo.md](docs/runbook-live-demo.md)**
- Source code (Live AI Analyst): **[src/](src/)**
- Evaluation CSV (canonical): **[evaluation/manual_vs_cloud_vs_local.csv](evaluation/manual_vs_cloud_vs_local.csv)**
- Infrastructure / Ansible docs: **[infra/](infra/)** → **[infra/ansible/](infra/ansible/)**

---

## Why this project
Remote/satellite clinics often operate with limited on-site IT. High-signal security and availability alerts can be triaged slowly or inconsistently when telemetry is uneven and triage is ad hoc. This project builds a repeatable workflow and measures timeliness and agreement across triage modes under clinic-scale constraints.

---

## What’s included (at a glance)
- **Wazuh-based monitoring** (Windows Sysmon + Security logs, Linux auth/service logs, and service-layer logs)
- **EHR-like 3-tier stack** to generate realistic clinic signals (auth failures + upstream outages)
- **Sanitized case bundles** (minimum necessary fields) to standardize triage inputs
- **Cloud LLM triage** (OpenAI API) and **local/offline LLM triage** (Ollama)
- **Live AI Analyst UI** (FastAPI + background worker) with Local/Cloud toggle and ON/OFF control
- **Auditable artifacts**: bundle/result/meta JSON outputs (excluded from git by default)

---

## Key results (initial evaluation)
- **3/3 classification & priority agreement** across manual baseline, cloud LLM, and local LLM for three controlled cases  
  (**Rule IDs:** 100202 / 100205 / 100210)
- **Timing tradeoff:** cloud = seconds per case, local/offline = minutes per case  
  Canonical CSV: **[evaluation/manual_vs_cloud_vs_local.csv](evaluation/manual_vs_cloud_vs_local.csv)**

---

## Repository map (recommended entry points)
| Area | What it contains | Link |
|---|---|---|
| Docs (start here) | Overview, runbook, diagrams | **[docs/](docs/)** |
| Figures | Diagram exports used in report/presentation | **[docs/figures/](docs/figures/)** |
| Source code | Publishable Live AI Analyst code | **[src/](src/)** |
| Evaluation | Canonical CSV outputs | **[evaluation/](evaluation/)** |
| Deploy | systemd/nginx templates | **[deploy/](deploy/)** |
| Infrastructure | Proxmox-first Ansible documentation | **[infra/](infra/)** |

> Lab workspace folders (supporting artifacts): `00-project-notes/`, `02-wazuh/`, `03-cases/`, `04-evaluation/`, `05-triage-assistant/`.

---

## Documentation
- Project overview: **[docs/overview.md](docs/overview.md)**
- Architecture: **[docs/architecture.md](docs/architecture.md)**
- Triage workflow: **[docs/triage-workflow.md](docs/triage-workflow.md)**
- Detections (full): **[docs/detections.md](docs/detections.md)**
- Detections (quick table): **[docs/detections-table.md](docs/detections-table.md)**
- Live demo runbook: **[docs/runbook-live-demo.md](docs/runbook-live-demo.md)**

---

## Figures (click to view)
- **Network architecture:** [fig01_network_architecture.png](docs/figures/fig01_network_architecture.png) · [PDF](docs/figures/fig01_network_architecture.pdf)  
- **EHR request & logging flow:** [fig02_ehr_request_logging_flow.png](docs/figures/fig02_ehr_request_logging_flow.png) · [PDF](docs/figures/fig02_ehr_request_logging_flow.pdf)  
- **Detection-to-triage pipeline:** [fig03_detection_triage_pipeline.png](docs/figures/fig03_detection_triage_pipeline.png) · [PDF](docs/figures/fig03_detection_triage_pipeline.pdf)  
- **Live AI Analyst architecture:** [fig04_live_ai_analyst_architecture.png](docs/figures/fig04_live_ai_analyst_architecture.png) · [PDF](docs/figures/fig04_live_ai_analyst_architecture.pdf)  
- **Timing comparison:** [fig05_timing_comparison.png](docs/figures/fig05_timing_comparison.png) · [PDF](docs/figures/fig05_timing_comparison.pdf)  
- **Cloud vs local decision logic:** [fig06_cloud_vs_local_decision_tree.png](docs/figures/fig06_cloud_vs_local_decision_tree.png) · [PDF](docs/figures/fig06_cloud_vs_local_decision_tree.pdf)

---

## How to run (high level)
See **[docs/runbook-live-demo.md](docs/runbook-live-demo.md)**.  
The Live AI Analyst runs as a FastAPI app with a background poller that reads new alerts from the Wazuh Indexer (OpenSearch).

<details>
<summary><strong>What you can demo quickly</strong></summary>

- Generate EHR login failures → confirm Wazuh rule firing (100202 / 100205)
- Toggle Local vs Cloud triage in the Live AI Analyst UI
- Show auditable artifacts (`bundle/result/meta`) written to disk
- Compare triage timing (manual vs cloud vs local)

</details>

---

## Safety / data handling
- No real PHI is used; service data is synthetic.
- Cloud triage uses **sanitized bundles only** (“minimum necessary” fields).
- Secrets (API keys/passwords) are **not stored** in this repository.

---

## License
MIT (see **[LICENSE](LICENSE)**).
