# Start Here

If you're reviewing this repository for the capstone, use the links below (recommended order).

---

## Reviewer path (recommended)
1) **Project overview:** [docs/overview.md](overview.md)  
2) **Architecture:** [docs/architecture.md](architecture.md)  
3) **Triage workflow (case bundles + outputs):** [docs/triage-workflow.md](triage-workflow.md)  
4) **Detections (full list):** [docs/detections.md](detections.md)  
5) **Detections (quick table):** [docs/detections-table.md](detections-table.md)  
6) **Live demo runbook:** [docs/runbook-live-demo.md](runbook-live-demo.md)  
7) **Key results (CSV):** [evaluation/manual_vs_cloud_vs_local.csv](../evaluation/manual_vs_cloud_vs_local.csv)  

---

## Figures / diagrams
- **All figures folder:** [docs/figures/](figures/)  
- Network architecture: [fig01_network_architecture.png](figures/fig01_network_architecture.png)  
- EHR request & logging flow: [fig02_ehr_request_logging_flow.png](figures/fig02_ehr_request_logging_flow.png)  
- Detection-to-triage pipeline: [fig03_detection_triage_pipeline.png](figures/fig03_detection_triage_pipeline.png)  
- Live AI Analyst architecture: [fig04_live_ai_analyst_architecture.png](figures/fig04_live_ai_analyst_architecture.png)  
- Timing comparison: [fig05_timing_comparison.png](figures/fig05_timing_comparison.png)  
- Cloud vs local decision logic: [fig06_cloud_vs_local_decision_tree.png](figures/fig06_cloud_vs_local_decision_tree.png)  

(PDF versions are in the same folder with matching filenames.)

---

## Code + deployment
- **Live AI Analyst source code:** [src/](../src/)  
- **Deployment templates (systemd/nginx):** [deploy/](../deploy/)  

---

## Lab workspace folders (supporting artifacts)
These folders contain lab build notes and supporting materials used during development:
- [00-project-notes/](../00-project-notes/)
- [02-wazuh/](../02-wazuh/)
- [03-cases/](../03-cases/)
- [04-evaluation/](../04-evaluation/)
- [05-triage-assistant/](../05-triage-assistant/)

---

## Infrastructure (documentation-first)
- **Ansible scaffolding:** [infra/ansible/](../infra/ansible/)
