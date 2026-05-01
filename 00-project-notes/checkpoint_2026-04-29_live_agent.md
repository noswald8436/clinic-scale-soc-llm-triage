# Checkpoint: Live AI Analyst working (2026-04-29)

## Components
- TRIAGE01 web UI + background agent: /opt/capstone/05-triage-assistant/live_agent/app.py
- Config: /opt/capstone/05-triage-assistant/live_agent/config.json
- State: /opt/capstone/05-triage-assistant/live_agent/state.json
- Prompt: /opt/capstone/05-triage-assistant/prompts/prompt_v1.txt

## Modes
- Cloud: OpenAI Responses API (model: gpt-4.1-mini)
- Local: Ollama (LLM01 model: mistral:7b-instruct)

## Inputs
- Indexer/OpenSearch: https://10.10.10.10:9200
- Query: wazuh-alerts-* filtered to rule IDs [100202,100205,100210]

## Outputs
- /opt/capstone/05-triage-assistant/outputs/live/YYYYMMDD/
  - live_<docid>.bundle.json
  - live_<docid>.result.json
  - live_<docid>.meta.json

## Notes
- UI toggle Local/Cloud works
- Agent ON/OFF works
- start_mode=now prevents backfill
