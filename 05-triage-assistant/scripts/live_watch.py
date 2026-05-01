#!/usr/bin/env python3
import os, time, json, requests
from pathlib import Path
from datetime import datetime, timezone

# ====== CONFIG ======
POLL_SECONDS = int(os.getenv("LIVE_POLL_SECONDS", "15"))
RULE_IDS = set(os.getenv("LIVE_RULE_IDS", "100202,100205,100210").split(","))

MODE = os.getenv("LIVE_MODE", "local")  # "cloud" or "local"
OUT_ROOT = Path("/opt/capstone/05-triage-assistant/outputs/live")

WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://10.10.10.10:55000").rstrip("/")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASS", "")

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://10.10.10.120:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral:7b-instruct")

PROMPT_PATH = Path("/opt/capstone/05-triage-assistant/prompts/prompt_v1.txt")
# ====================

def now_utc():
    return datetime.now(timezone.utc).isoformat()

def today_folder():
    d = datetime.now().strftime("%Y%m%d")
    p = OUT_ROOT / d
    p.mkdir(parents=True, exist_ok=True)
    return p

def wazuh_request(path, params=None):
    if not WAZUH_API_USER or not WAZUH_API_PASS:
        raise RuntimeError("WAZUH_API_USER/WAZUH_API_PASS not set")

    url = f"{WAZUH_API_URL}{path}"
    r = requests.get(url, params=params, auth=(WAZUH_API_USER, WAZUH_API_PASS), verify=False, timeout=30)
    r.raise_for_status()
    return r.json()

def build_mini_bundle(alert: dict) -> dict:
    """
    Normalize into a minimal case bundle that is safe to send to LLM.
    You can later expand this with context windows.
    """
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {}) or {}

    # Try common fields you’ve seen in your alerts
    src_ip = data.get("src_ip") or data.get("srcip") or data.get("srcip_address") or ""
    username = data.get("username") or data.get("user") or ""
    path = data.get("path") or data.get("url") or ""
    reason = data.get("reason") or data.get("status") or ""

    case_id = f"live_{alert.get('id','unknown')}"
    return {
        "case_id": case_id,
        "scenario_label": f"live_rule_{rule.get('id','')}",
        "truth_classification": "",
        "alert": {
            "timestamp": alert.get("timestamp", ""),
            "rule_id": str(rule.get("id","")),
            "rule_level": rule.get("level",""),
            "rule_description": rule.get("description",""),
            "agent_name": agent.get("name",""),
            "agent_ip": agent.get("ip",""),
            "location": alert.get("location","")
        },
        "key_fields": {
            "src_ip": src_ip,
            "username": username,
            "path": path,
            "reason": reason
        },
        "raw_log": ""  # keep blank unless you explicitly want it
    }

def load_prompt():
    return PROMPT_PATH.read_text(encoding="utf-8")

def triage_local(bundle: dict) -> dict:
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
    text = r.json().get("response","").strip()
    return json.loads(text)

def triage_cloud(bundle: dict) -> dict:
    # Reuse your working cloud approach without re-implementing the SDK:
    # Call your existing triage_cloud.py style by using OpenAI Responses API via HTTP.
    # To keep this minimal, we’ll use requests to call OpenAI directly.
    import os
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")

    prompt = load_prompt() + "\n" + json.dumps(bundle, indent=2)

    url = "https://api.openai.com/v1/responses"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": OPENAI_MODEL,
        "input": prompt,
        "text": {"format": {"type": "json_object"}}
    }
    r = requests.post(url, headers=headers, json=payload, timeout=60)
    r.raise_for_status()
    resp = r.json()
    text = resp.get("output_text","").strip()
    return json.loads(text)

def write_outputs(out_dir: Path, bundle: dict, result: dict, meta: dict):
    case_id = bundle["case_id"]
    (out_dir / f"{case_id}.bundle.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    (out_dir / f"{case_id}.{MODE}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out_dir / f"{case_id}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

def main():
    out_dir = today_folder()
    seen_path = out_dir / "seen_ids.json"
    seen = set(json.loads(seen_path.read_text())) if seen_path.exists() else set()

    print(f"[LiveWatch] mode={MODE} poll={POLL_SECONDS}s rules={sorted(RULE_IDS)} out={out_dir}")
    print(f"[LiveWatch] Wazuh API: {WAZUH_API_URL}")

    while True:
        try:
            # Pull recent alerts (limit small; we dedupe by id)
            # Wazuh API: /alerts endpoint exists in most installs
            data = wazuh_request("/alerts", params={"limit": 50, "sort": "-timestamp"})
            items = data.get("data", {}).get("affected_items", [])

            new_items = []
            for a in items:
                rid = str(a.get("rule", {}).get("id", ""))
                aid = str(a.get("id",""))
                if rid in RULE_IDS and aid and aid not in seen:
                    new_items.append(a)

            # Process oldest-first so output order feels natural
            new_items.reverse()

            for a in new_items:
                aid = str(a.get("id",""))
                rid = str(a.get("rule", {}).get("id",""))
                bundle = build_mini_bundle(a)

                t0 = time.time()
                if MODE == "cloud":
                    result = triage_cloud(bundle)
                else:
                    result = triage_local(bundle)
                elapsed = time.time() - t0

                meta = {
                    "generated_utc": now_utc(),
                    "wazuh_alert_id": aid,
                    "rule_id": rid,
                    "mode": MODE,
                    "elapsed_seconds": round(elapsed, 4)
                }

                write_outputs(out_dir, bundle, result, meta)
                seen.add(aid)
                print(f"[OK] rule={rid} alert_id={aid} -> {bundle['case_id']} ({meta['elapsed_seconds']}s)")

            seen_path.write_text(json.dumps(sorted(seen), indent=2), encoding="utf-8")

        except Exception as e:
            print(f"[ERR] {e}")

        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    # Disable noisy HTTPS warnings because we use verify=False for internal Wazuh API
    requests.packages.urllib3.disable_warnings()
    main()
