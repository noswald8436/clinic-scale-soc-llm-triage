# Triage Workflow

## Goal
Standardize alert triage so that manual and AI-assisted triage:
- use the same input structure,
- produce comparable outputs,
- and can be measured for timing and consistency.

## Case bundles (sanitized input)
Alerts are normalized into a sanitized case bundle that includes only minimum necessary triage fields. Typical fields include:
- rule metadata (rule_id, level, description)
- agent/host context (agent name/IP, location)
- key fields (src_ip, username, request path, failure reason/status)

Bundles are designed to exclude any sensitive clinical content.

## Triage output schema (structured JSON)
Both cloud and local triage modes produce a consistent JSON output schema:
- classification (benign / suspicious / incident)
- priority (low / medium / high)
- confidence (0–1)
- summary (bullet list)
- recommended_next_steps (bullet list)
- optional: error field if triage fails

## Cloud vs local decision (operator-controlled)
Mode selection is operator-controlled in the Live AI Analyst UI:
- Cloud mode is used when sanitized bundles can be processed externally and fast turnaround is required.
- Local/offline mode is used when external processing is restricted or offline capability is needed.
- If neither LLM is available, manual triage proceeds using the same case bundle.

**Figure:** `docs/figures/fig06_cloud_vs_local_decision_tree.*`
