# Ansible (Documentation-first)

This is a documentation-first Ansible structure intended to make the capstone environment reproducible.

Scope:
- Linux nodes: WAZUH01, TRIAGE01, LLM01, LNX-WEB-01, LNX-APP-01, LNX-DB-01
- Windows nodes: documented steps only (Wazuh agent + Sysmon)

Workflow:
1) Provision VMs in Proxmox (manual or template-based)
2) Populate `inventory/inventory.ini`
3) Populate `group_vars/all/secrets.yml` (not tracked)
4) Run `ansible-playbook playbooks/site.yml`
5) Verify services + detections

Docs:
- `docs/00_prereqs.md`
- `docs/01_inventory.md`
- `docs/02_secrets.md`
- `docs/03_run_order.md`
- `docs/04_verification.md`
- `docs/05_windows_notes.md`
