import os
import json
import time
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List

import requests
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

APP = FastAPI()

# --------- Paths ----------
BASE_DIR = Path("/opt/capstone/05-triage-assistant/live_agent")
CONFIG_PATH = BASE_DIR / "config.json"
STATE_PATH = BASE_DIR / "state.json"
PROMPT_PATH = Path("/opt/capstone/05-triage-assistant/prompts/prompt_v1.txt")
OUT_ROOT = Path("/opt/capstone/05-triage-assistant/outputs/live")

# --------- External endpoints / creds from env ----------
INDEXER_URL = os.getenv("INDEXER_URL", "https://10.10.10.10:9200").rstrip("/")
INDEXER_USER = os.getenv("INDEXER_USER", "")
INDEXER_PASS = os.getenv("INDEXER_PASS", "")

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://10.10.10.120:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral:7b-instruct")

# --------- Worker control ----------
_worker_thread = None
_stop_event = threading.Event()
_lock = threading.Lock()

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_ts(ts: str):
    # ts like "2026-04-28T18:41:20.665Z"
    try:
        # normalize Z
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def local_time_str(dt: datetime) -> str:
    # Use system local time zone on TRIAGE01
    try:
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return ""

def load_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default

def save_json(p: Path, obj):
    p.write_text(json.dumps(obj, indent=2), encoding="utf-8")

def load_config() -> Dict[str, Any]:
    cfg = load_json(CONFIG_PATH, {})
    # Defaults
    cfg.setdefault("enabled", False)
    cfg.setdefault("mode", "local")
    cfg.setdefault("poll_seconds", 15)
    cfg.setdefault("max_hits", 50)
    cfg.setdefault("rule_ids", [100202, 100205, 100210])
    cfg.setdefault("show_items", 20)
    cfg["mode"] = str(cfg["mode"]).lower()
    return cfg

def load_state() -> Dict[str, Any]:
    st = load_json(STATE_PATH, {})
    st.setdefault("seen_ids", [])
    st.setdefault("last_poll_utc", None)
    st.setdefault("last_error", None)
    return st

def output_day_dir() -> Path:
    d = datetime.now().strftime("%Y%m%d")
    p = OUT_ROOT / d
    p.mkdir(parents=True, exist_ok=True)
    return p

def load_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")

def indexer_search(rule_ids: List[int], size: int) -> Dict[str, Any]:
    if not INDEXER_USER or not INDEXER_PASS:
        raise RuntimeError("INDEXER_USER/INDEXER_PASS not set in environment")

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

def build_bundle_from_hit(hit: Dict[str, Any]) -> Dict[str, Any]:
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
        }
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
        raise RuntimeError("OPENAI_API_KEY not set in environment")

    prompt = load_prompt() + "\n" + json.dumps(bundle, indent=2)
    url = "https://api.openai.com/v1/responses"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": OPENAI_MODEL, "input": prompt, "text": {"format": {"type": "json_object"}}}

    r = requests.post(url, headers=headers, json=payload, timeout=90)

    if r.status_code >= 400:
        try:
            return {"error": f"OpenAI HTTP {r.status_code}", "details": r.json()}
        except Exception:
            return {"error": f"OpenAI HTTP {r.status_code}", "details": r.text[:500]}

    resp = r.json()

    # 1) Prefer top-level output_text if present (some responses include it)
    text = (resp.get("output_text") or "").strip()

    # 2) Otherwise, extract from nested output[].content[].text
    if not text:
        try:
            out0 = (resp.get("output") or [])[0]
            content0 = (out0.get("content") or [])[0]
            text = (content0.get("text") or "").strip()
        except Exception:
            text = ""

    if not text:
        return {"error": "OpenAI returned no extractable text", "details": resp}

    try:
        return json.loads(text)
    except Exception:
        return {"error": "OpenAI output was not valid JSON", "raw": text[:1000], "details": resp}

def write_case_files(day_dir: Path, doc_id: str, bundle: Dict[str, Any], result: Dict[str, Any], meta: Dict[str, Any]):
    case_id = f"live_{doc_id}"
    (day_dir / f"{case_id}.bundle.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    (day_dir / f"{case_id}.result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (day_dir / f"{case_id}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

def worker_loop():
    requests.packages.urllib3.disable_warnings()

    while not _stop_event.is_set():
        cfg = load_config()
        st = load_state()

        if not cfg.get("enabled", False):
            time.sleep(1)
            continue

        poll_seconds = int(cfg.get("poll_seconds", 15))
        max_hits = int(cfg.get("max_hits", 50))
        rule_ids = [int(x) for x in cfg.get("rule_ids", [])]
        mode = str(cfg.get("mode", "local")).lower()

        try:
            # Load state fresh each cycle (in case UI changed it)
            st = load_state()
            seen = set(st.get("seen_ids", []))

            resp = indexer_search(rule_ids=rule_ids, size=max_hits)
            hits = resp.get("hits", {}).get("hits", [])

            # Only unseen IDs
            new_hits = [h for h in hits if h.get("_id") and h["_id"] not in seen]
            new_hits.reverse()  # process oldest-first

            day_dir = output_day_dir()

            for h in new_hits:
                doc_id = h["_id"]

                # Mark seen BEFORE triage to avoid duplicates if triage hangs/crashes mid-loop
                seen.add(doc_id)
                st["seen_ids"] = sorted(seen)
                st["last_poll_utc"] = now_utc_iso()
                st["last_error"] = None
                save_json(STATE_PATH, st)

                bundle = build_bundle_from_hit(h)

                t0 = time.time()
                mode = str(cfg.get("mode", "local")).lower()  # re-check mode each item (fast)
                try:
                    if mode == "cloud":
                        result = triage_cloud(bundle)
                        model_used = OPENAI_MODEL
                    else:
                        result = triage_local(bundle)
                        model_used = OLLAMA_MODEL
                except Exception as triage_err:
                    result = {"error": str(triage_err)}
                    model_used = OPENAI_MODEL if mode == "cloud" else OLLAMA_MODEL

                elapsed = round(time.time() - t0, 4)
                meta = {
                    "generated_utc": now_utc_iso(),
                    "indexer_doc_id": doc_id,
                    "mode": mode,
                    "model": model_used,
                    "elapsed_seconds": elapsed,
                    "config_mode": mode,
                    "config_enabled": cfg.get("enabled", False)
                }

                write_case_files(day_dir, doc_id, bundle, result, meta)

            # end-of-cycle state update
            st["seen_ids"] = sorted(seen)
            st["last_poll_utc"] = now_utc_iso()
            st["last_error"] = None
            save_json(STATE_PATH, st)

        except Exception as e:
            st = load_state()
            st["last_error"] = str(e)
            st["last_poll_utc"] = now_utc_iso()
            save_json(STATE_PATH, st)


        except Exception as e:
            st["last_error"] = str(e)
            st["last_poll_utc"] = now_utc_iso()
            save_json(STATE_PATH, st)

        time.sleep(poll_seconds)

def ensure_worker():
    global _worker_thread
    with _lock:
        if _worker_thread and _worker_thread.is_alive():
            return
        _stop_event.clear()
        _worker_thread = threading.Thread(target=worker_loop, daemon=True)
        _worker_thread.start()

@APP.on_event("startup")
def startup():
    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    ensure_worker()

# ---------- UI ----------
def latest_day_dir() -> Path:
    days = sorted([p for p in OUT_ROOT.glob("*") if p.is_dir()])
    return days[-1] if days else None

@APP.get("/", response_class=HTMLResponse)
def home():
    cfg = load_config()
    st = load_state()
    day = latest_day_dir()

    mode = cfg.get("mode", "local")
    enabled = cfg.get("enabled", False)

    status_line = "ENABLED" if enabled else "DISABLED"
    status_color = "#070" if enabled else "#900"

    html = f"""
    <html><head>
      <title>Live AI Analyst</title>
      <meta http-equiv="refresh" content="5">
      <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .row {{ display:flex; gap:16px; align-items:center; flex-wrap:wrap; }}
        .pill {{ padding:2px 10px; border-radius:12px; background:#eef; display:inline-block; }}
        .card {{ border:1px solid #ddd; padding:12px; margin:10px 0; border-radius:8px; }}
        .meta {{ color:#555; font-size:0.9em; margin-bottom:6px; }}
        pre {{ background:#f7f7f7; padding:10px; border-radius:6px; overflow-x:auto; }}
        a.button {{
          display:inline-block; padding:6px 10px; border:1px solid #888; border-radius:6px;
          text-decoration:none; color:#111; background:#fafafa;
        }}
      </style>
    </head><body>
      <h1>Live AI Analyst</h1>

      <div class="row">
        <div><b>Status:</b> <span class="pill" style="background:#fee;color:{status_color};"><b>{status_line}</b></span></div>
        <div><b>Mode:</b> <span class="pill">{mode}</span></div>
        <div><b>Last poll (UTC):</b> {st.get("last_poll_utc")}</div>
        <div><b>Last error:</b> {st.get("last_error")}</div>
      </div>

      <div class="row" style="margin-top:10px;">
        <a class="button" href="/agent/on">Turn ON</a>
        <a class="button" href="/agent/off">Turn OFF</a>
        <a class="button" href="/mode/local">Use Local</a>
        <a class="button" href="/mode/cloud">Use Cloud</a>
      </div>

      <p class="meta">Auto-refresh: every 5 seconds. Showing latest results from the newest dated folder.</p>

      <h2>Latest triage results</h2>
    """

    if not day:
        return html + "<p>No output folder yet.</p></body></html>"

    metas = sorted(day.glob("live_*.meta.json"), key=lambda p: p.stat().st_mtime, reverse=True)[: int(cfg.get("show_items", 20))]

    if not metas:
        return html + "<p>No triage outputs yet (turn ON the agent and generate an alert).</p></body></html>"

    for m in metas:
        meta = load_json(m, {})
        base = m.name.replace(".meta.json", "")
        bundle = load_json(day / f"{base}.bundle.json", {})
        result = load_json(day / f"{base}.result.json", {})

        alert = bundle.get("alert", {})
        ts_raw = alert.get("timestamp", "")
        dt = parse_ts(ts_raw) if ts_raw else None
        ts_local = local_time_str(dt) if dt else ""
        ts_utc = dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if dt else ts_raw

        rule_id = alert.get("rule_id","")
        agent = alert.get("agent_name","")

        classification = result.get("classification","")
        priority = result.get("priority","")
        confidence = result.get("confidence","")
        likely = result.get("likely_attack_or_issue","")
        err = result.get("error","")

        html += f"""
        <div class="card">
          <div class="meta">
            <b>{ts_local}</b> (<span>{ts_utc}</span>) |
            rule <b>{rule_id}</b> | agent <b>{agent}</b> |
            mode <b>{meta.get("mode","")}</b> | model <b>{meta.get("model","")}</b> |
            elapsed <b>{meta.get("elapsed_seconds","")}s</b>
          </div>

          <div><b>Classification:</b> {classification} | <b>Priority:</b> {priority} | <b>Confidence:</b> {confidence}</div>
          <div><b>Likely issue:</b> {likely}</div>
        """

        if err:
            html += f"""<div style="color:#b00;"><b>Error:</b> {err}</div>"""

        html += f"""
          <details>
            <summary>Show result JSON</summary>
            <pre>{json.dumps(result, indent=2)}</pre>
          </details>
        </div>
        """

    html += "</body></html>"
    return html

@APP.get("/agent/on")
def agent_on():
    cfg = load_config()
    cfg["enabled"] = True
    save_json(CONFIG_PATH, cfg)
    ensure_worker()

    # If start_mode is "now", mark current matching docs as seen to avoid backfill
    if cfg.get("start_mode", "backfill") == "now":
        try:
            resp = indexer_search(rule_ids=[int(x) for x in cfg.get("rule_ids", [])], size=int(cfg.get("max_hits", 50)))
            hits = resp.get("hits", {}).get("hits", [])
            st = load_state()
            seen = set(st.get("seen_ids", []))
            for h in hits:
                if h.get("_id"):
                    seen.add(h["_id"])
            st["seen_ids"] = sorted(seen)
            st["last_poll_utc"] = now_utc_iso()
            st["last_error"] = None
            save_json(STATE_PATH, st)
        except Exception as e:
            st = load_state()
            st["last_error"] = f"start_mode now failed: {e}"
            save_json(STATE_PATH, st)

    return RedirectResponse(url="/", status_code=303)

@APP.get("/agent/off")
def agent_off():
    cfg = load_config()
    cfg["enabled"] = False
    save_json(CONFIG_PATH, cfg)
    return RedirectResponse(url="/", status_code=303)

@APP.get("/mode/{mode}")
def set_mode(mode: str):
    mode = mode.lower()
    if mode not in ("local", "cloud"):
        return JSONResponse({"ok": False, "error": "mode must be local or cloud"}, status_code=400)
    cfg = load_config()
    cfg["mode"] = mode
    save_json(CONFIG_PATH, cfg)
    ensure_worker()
    return RedirectResponse(url="/", status_code=303)

@APP.get("/api/status")
def api_status():
    return {"config": load_config(), "state": load_state()}
