#!/usr/bin/env python3
"""
LiveWatchIndexer (capstone)
- Polls OpenSearch (Wazuh Indexer) for new wazuh-alerts-* documents matching rule IDs
- Builds a minimal sanitized bundle per new alert
- Runs LLM triage in either LOCAL (Ollama) or CLOUD (OpenAI) mode
- Writes output files under /opt/capstone/05-triage-assistant/outputs/live/YYYYMMDD/

UI integration:
- Reads /opt/capstone/05-triage-assistant/live_config.json each loop.
  Change "mode" between "local" and "cloud" from a web UI without restarting.
"""

import os
import time
import json
import traceback
import requests
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple

# ---------- Paths ----------
OUT_ROOT = Path("/opt/capstone/05-triage-assistant/outputs/live")
PROMPT_PATH = Path("/opt/capstone/05-triage-assistant/prompts/prompt_v1.txt")
CONFIG_PATH = Path("/opt/capstone/05-triage-assistant/live_config.json")

# ---------- Defaults from env (config can override) ----------
DEFAULT_MODE = os.getenv("LIVE_MODE", "local").lower()  # local | cloud
DEFAULT_POLL_SECONDS = int(os.getenv("LIVE_POLL_SECONDS", "15"))
DEFAULT_RULE_IDS = [int(x.strip()) for x in os.getenv("LIVE_RULE_IDS", "100202,100205,100210").split(",")]
DEFAULT_MAX_HITS = int(os.getenv("LIVE_MAX_HITS", "50"))

INDEXER_URL = os.getenv("INDEXER_URL", "https://10.10.10.10:9200").rstrip("/")
INDEXER_USER = os.getenv("INDEXER_USER", "")
INDEXER_PASS = os.getenv("INDEXER_PASS", "")

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://10.10.10.120:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral:7b-instruct")

# ---------- Helpers ----------
def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def today_folder() -> Path:
    d = datetime.now().strftime("%Y%m%d")
    p = OUT_ROOT / d
    p.mkdir(parents=True, exist_ok=True)
    return p

def load_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")

def load_config() -> Dict[str, Any]:
    """
    Config file is optional. If missing, env defaults are used.
    """
    cfg = {
        "mode": DEFAULT_MODE,
        "poll_seconds": DEFAULT_POLL_SECONDS,
        "rule_ids": DEFAULT_RULE_IDS,
        "max_hits": DEFAULT_MAX_HITS
    }
    if CONFIG_PATH.exists():
        try:
            file_cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            cfg.update({k: v for k, v in file_cfg.items() if v is not None})
        except Exception:
            # If config is malformed, keep running with defaults
            pass
    cfg["mode"] = str(cfg.get("mode", DEFAULT_MODE)).lower()
    cfg["poll_seconds"] = int(cfg.get("poll_seconds", DEFAULT_POLL_SECONDS))
    cfg["max_hits"] = int(cfg.get("max_hits", DEFAULT_MAX_HITS))
    cfg["rule_ids"] = [int(x) for x in cfg.get("rule_ids", DEFAULT_RULE_IDS)]
    return cfg

def indexer_search(rule_ids: List[int], size: int) -> Dict[str, Any]:
    if not INDEXER_USER or not INDEXER_PASS:
        raise RuntimeError("INDEXER_USER/INDEXER_PASS not set")

    url = f"{INDEXER_URL}/wazuh-alerts-*/_search"
    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": True,
        "query": {"terms": {"rule.id": rule_ids}}
    }

    r = requests.post(
        url,
        auth=(INDEXER_USER, INDEXER_PASS),
        headers={"Content-Type": "application/json"},
        json=body,
        verify=False,
        timeout=30
    )
    r.raise_for_status()
    return r.json()

def build_mini_bundle(hit: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produce a minimal sanitized bundle. Avoid dumping full raw logs by default.
    """
    src = hit.get("_source", {}) or {}
    rule = src.get("rule", {}) or {}
    agent = src.get("agent", {}) or {}
    data = src.get("data", {}) or {}

    src_ip = data.get("src_ip") or data.get("srcip") or ""
    username = data.get("username") or data.get("user") or ""
    path = data.get("path") or data.get("url") or ""
    reason = data.get("reason") or str(data.get("status_code") or data.get("status") or "")

    doc_id = hit.get("_id", "unknown")
    case_id = f"live_{doc_id}"

    return {
        "case_id": case_id,
        "scenario_label": f"live_rule_{rule.get('id','')}",
        "truth_classification": "",
        "alert": {
            "timestamp": src.get("@timestamp", src.get("timestamp", "")),
            "rule_id": str(rule.get("id", "")),
            "rule_level": rule.get("level", ""),
            "rule_description": rule.get("description", ""),
            "agent_name": agent.get("name", ""),
            "agent_ip": agent.get("ip", ""),
            "location": src.get("location", "")
        },
        "key_fields": {
            "src_ip": src_ip,
            "username": username,
            "path": path,
            "reason": reason
        },
        "raw_excerpt": ""
    }

def triage_local(bundle: Dict[str, Any]) -> Dict[str, Any]:
    prompt = load_prompt() + "\n" + json.dumps(bundle, indent=2)
    url = f"{OLLAMA_HOST}/api/generate"
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2}
    }
    r = requests.post(url, json=payload, timeout=240)
    r.raise_for_status()
    text = r.json().get("response", "").strip()
    return json.loads(text)

def triage_cloud(bundle: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")

    prompt = load_prompt() + "\n" + json.dumps(bundle, indent=2)
    url = "https://api.openai.com/v1/responses"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": OPENAI_MODEL,
        "input": prompt,
        "text": {"format": {"type": "json_object"}}
    }
    r = requests.post(url, headers=headers, json=payload, timeout=90)
    r.raise_for_status()
    text = r.json().get("output_text", "").strip()
    return json.loads(text)

def read_seen_ids(day_dir: Path) -> set:
    seen_path = day_dir / "seen_ids.json"
    if not seen_path.exists():
        return set()
    try:
        return set(json.loads(seen_path.read_text(encoding="utf-8")))
    except Exception:
        return set()

def write_seen_ids(day_dir: Path, seen: set):
    (day_dir / "seen_ids.json").write_text(json.dumps(sorted(seen), indent=2), encoding="utf-8")

def write_outputs(day_dir: Path, bundle: Dict[str, Any], result: Dict[str, Any], meta: Dict[str, Any]):
    """
    Write:
      - live_<id>.bundle.json
      - live_<id>.result.json
      - live_<id>.meta.json
    """
    case_id = bundle["case_id"]
    (day_dir / f"{case_id}.bundle.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    (day_dir / f"{case_id}.result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (day_dir / f"{case_id}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

def main():
    day_dir = today_folder()
    seen = read_seen_ids(day_dir)

    print(f"[LiveWatchIndexer] out={day_dir}")
    print(f"[LiveWatchIndexer] indexer={INDEXER_URL}")
    print(f"[LiveWatchIndexer] defaults: mode={DEFAULT_MODE} poll={DEFAULT_POLL_SECONDS}s rules={DEFAULT_RULE_IDS}")

    while True:
        cfg = load_config()
        mode = cfg["mode"]
        poll_seconds = cfg["poll_seconds"]
        rule_ids = cfg["rule_ids"]
        max_hits = cfg["max_hits"]

        try:
            resp = indexer_search(rule_ids=rule_ids, size=max_hits)
            hits = resp.get("hits", {}).get("hits", [])

            # New docs only
            new_hits = [h for h in hits if h.get("_id") and h["_id"] not in seen]
            new_hits.reverse()  # oldest-first for nicer ordering

            for h in new_hits:
                hid = h["_id"]
                bundle = build_mini_bundle(h)

                t0 = time.time()
                try:
                    if mode == "cloud":
                        result = triage_cloud(bundle)
                        model_used = OPENAI_MODEL
                    else:
                        result = triage_local(bundle)
                        model_used = OLLAMA_MODEL
                except Exception as triage_err:
                    # Save a failure record and continue
                    meta = {
                        "generated_utc": now_utc(),
                        "indexer_doc_id": hid,
                        "rule_id": bundle["alert"]["rule_id"],
                        "mode": mode,
                        "model": model_used if "model_used" in locals() else "",
                        "elapsed_seconds": round(time.time() - t0, 4),
                        "error": str(triage_err),
                    }
                    write_outputs(day_dir, bundle, {"error": str(triage_err)}, meta)
                    seen.add(hid)
                    print(f"[ERR] triage failed rule={bundle['alert']['rule_id']} id={hid}: {triage_err}")
                    continue

                elapsed = time.time() - t0
                meta = {
                    "generated_utc": now_utc(),
                    "indexer_doc_id": hid,
                    "rule_id": bundle["alert"]["rule_id"],
                    "mode": mode,
                    "model": model_used,
                    "elapsed_seconds": round(elapsed, 4),
                    "prompt_file": str(PROMPT_PATH)
                }

                write_outputs(day_dir, bundle, result, meta)
                seen.add(hid)
                print(f"[OK] mode={mode} rule={bundle['alert']['rule_id']} id={hid} ({meta['elapsed_seconds']}s)")

            write_seen_ids(day_dir, seen)

        except Exception as e:
            print(f"[ERR] watcher loop: {e}")
            # Optional: uncomment for full trace during debugging
            # print(traceback.format_exc())

        time.sleep(poll_seconds)

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()