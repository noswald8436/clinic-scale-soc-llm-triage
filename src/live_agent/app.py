import os
import json
import time
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import requests
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse

APP = FastAPI()

# --------------------
# Paths
# --------------------
BASE_DIR = Path("/opt/capstone/05-triage-assistant/live_agent")
CONFIG_PATH = BASE_DIR / "config.json"
STATE_PATH = BASE_DIR / "state.json"
UI_PATH = BASE_DIR / "ui.html"

PROMPT_PATH = Path("/opt/capstone/05-triage-assistant/prompts/prompt_v1.txt")
OUT_ROOT = Path("/opt/capstone/05-triage-assistant/outputs/live")

# --------------------
# External endpoints / creds from env
# --------------------
INDEXER_URL = os.getenv("INDEXER_URL", "https://10.10.10.10:9200").rstrip("/")
INDEXER_USER = os.getenv("INDEXER_USER", "")
INDEXER_PASS = os.getenv("INDEXER_PASS", "")

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://10.10.10.120:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral:7b-instruct")

# --------------------
# Worker control
# --------------------
_worker_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()
_lock = threading.Lock()

# --------------------
# Utilities
# --------------------
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_ts(ts: str) -> Optional[datetime]:
    try:
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def local_time_str(dt: datetime) -> str:
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

def utc_time_str(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def load_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default

def save_json(p: Path, obj):
    p.write_text(json.dumps(obj, indent=2), encoding="utf-8")

def ensure_prereqs_exist():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    OUT_ROOT.mkdir(parents=True, exist_ok=True)

    if not CONFIG_PATH.exists():
        save_json(CONFIG_PATH, {
            "enabled": False,
            "mode": "local",
            "poll_seconds": 15,
            "max_hits": 50,
            "rule_ids": [100202, 100205, 100210],
            "show_items": 20,
            "start_mode": "now"
        })

    if not STATE_PATH.exists():
        save_json(STATE_PATH, {"seen_ids": [], "last_poll_utc": None, "last_error": None})

    if not UI_PATH.exists():
        UI_PATH.write_text(
            "<html><body><h1>Live AI Analyst</h1><p>ui.html missing</p></body></html>",
            encoding="utf-8",
        )

def output_day_dir() -> Path:
    d = datetime.now().strftime("%Y%m%d")
    p = OUT_ROOT / d
    p.mkdir(parents=True, exist_ok=True)
    return p

def latest_day_dir() -> Optional[Path]:
    days = sorted([p for p in OUT_ROOT.glob("*") if p.is_dir()])
    return days[-1] if days else None

def sev_class(priority: str) -> str:
    p = (priority or "").lower()
    if p == "high":
        return "high"
    if p == "medium":
        return "medium"
    if p == "low":
        return "low"
    return ""

def load_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")

def load_config() -> Dict[str, Any]:
    cfg = load_json(CONFIG_PATH, {})
    cfg.setdefault("enabled", False)
    cfg.setdefault("mode", "local")
    cfg.setdefault("poll_seconds", 15)
    cfg.setdefault("max_hits", 50)
    cfg.setdefault("rule_ids", [100202, 100205, 100210])
    cfg.setdefault("show_items", 20)
    cfg.setdefault("start_mode", "now")

    cfg["enabled"] = bool(cfg.get("enabled", False))
    cfg["mode"] = str(cfg.get("mode", "local")).lower()
    cfg["poll_seconds"] = int(cfg.get("poll_seconds", 15))
    cfg["max_hits"] = int(cfg.get("max_hits", 50))
    cfg["rule_ids"] = [int(x) for x in cfg.get("rule_ids", [])]
    cfg["show_items"] = int(cfg.get("show_items", 20))
    cfg["start_mode"] = str(cfg.get("start_mode", "now")).lower()
    return cfg

def load_state() -> Dict[str, Any]:
    st = load_json(STATE_PATH, {})
    st.setdefault("seen_ids", [])
    st.setdefault("last_poll_utc", None)
    st.setdefault("last_error", None)
    return st

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

def write_case_files(day_dir: Path, doc_id: str, bundle: Dict[str, Any], result: Dict[str, Any], meta: Dict[str, Any]):
    case_id = f"live_{doc_id}"
    (day_dir / f"{case_id}.bundle.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    (day_dir / f"{case_id}.result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (day_dir / f"{case_id}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

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
        return {"error": "OPENAI_API_KEY not set in environment"}

    prompt = load_prompt() + "\n" + json.dumps(bundle, indent=2)
    url = "https://api.openai.com/v1/responses"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": OPENAI_MODEL, "input": prompt, "text": {"format": {"type": "json_object"}}}

    r = requests.post(url, headers=headers, json=payload, timeout=90)

    if r.status_code >= 400:
        try:
            return {"error": f"OpenAI HTTP {r.status_code}", "details": r.json()}
        except Exception:
            return {"error": f"OpenAI HTTP {r.status_code}", "details": r.text[:800]}

    resp = r.json()

    text = (resp.get("output_text") or "").strip()
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
        return {"error": "OpenAI output was not valid JSON", "raw": text[:1200], "details": resp}

def baseline_seen_ids_now(cfg: Dict[str, Any]):
    """Mark current hits as seen so we don't backfill old alerts when enabling."""
    try:
        resp = indexer_search(rule_ids=cfg["rule_ids"], size=cfg["max_hits"])
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
        st["last_poll_utc"] = now_utc_iso()
        save_json(STATE_PATH, st)

# --------------------
# Worker Loop
# --------------------
def worker_loop():
    requests.packages.urllib3.disable_warnings()

    while not _stop_event.is_set():
        cfg = load_config()

        if not cfg.get("enabled", False):
            time.sleep(1)
            continue

        poll_seconds = cfg["poll_seconds"]
        max_hits = cfg["max_hits"]
        rule_ids = cfg["rule_ids"]

        try:
            st = load_state()
            seen = set(st.get("seen_ids", []))

            resp = indexer_search(rule_ids=rule_ids, size=max_hits)
            hits = resp.get("hits", {}).get("hits", [])

            new_hits = [h for h in hits if h.get("_id") and h["_id"] not in seen]
            new_hits.reverse()  # oldest-first
            day_dir = output_day_dir()

            for h in new_hits:
                doc_id = h["_id"]

                # Mark seen BEFORE triage
                seen.add(doc_id)
                st["seen_ids"] = sorted(seen)
                st["last_poll_utc"] = now_utc_iso()
                st["last_error"] = None
                save_json(STATE_PATH, st)

                bundle = build_bundle_from_hit(h)
                mode = cfg.get("mode", "local")

                t0 = time.time()
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
                    "elapsed_seconds": elapsed
                }

                write_case_files(day_dir, doc_id, bundle, result, meta)

            st["seen_ids"] = sorted(seen)
            st["last_poll_utc"] = now_utc_iso()
            st["last_error"] = None
            save_json(STATE_PATH, st)

        except Exception as e:
            st = load_state()
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
    ensure_prereqs_exist()
    ensure_worker()

# --------------------
# UI helpers
# --------------------
def load_entries(day: Path, limit: int) -> List[Dict[str, Any]]:
    metas = sorted(day.glob("live_*.meta.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
    entries = []
    for m in metas:
        meta = load_json(m, {})
        base = m.name.replace(".meta.json", "")
        bundle = load_json(day / f"{base}.bundle.json", {})
        result = load_json(day / f"{base}.result.json", {})

        alert = bundle.get("alert", {})
        kf = bundle.get("key_fields", {}) or {}
        ts_raw = alert.get("timestamp", "")
        dt = parse_ts(ts_raw) if ts_raw else None

        ts_local = local_time_str(dt) if dt else ts_raw
        ts_utc = utc_time_str(dt) if dt else ts_raw

        entry = {
            "base": base,
            "meta": meta,
            "bundle": bundle,
            "result": result,
            "result_json": json.dumps(result, indent=2),
            "ts_local": ts_local,
            "ts_utc": ts_utc,
            "rule_id": alert.get("rule_id",""),
            "agent": alert.get("agent_name",""),
            "src_ip": kf.get("src_ip",""),
            "username": kf.get("username",""),
            "path": kf.get("path",""),
            "reason": kf.get("reason",""),
            "sev_class": sev_class((result.get("priority") or ""))
        }
        entries.append(entry)
    return entries

def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def html_ul(items) -> str:
    """Render list[str] to <ul><li>..</li></ul>."""
    if not isinstance(items, list) or not items:
        return "<ul><li>(none)</li></ul>"
    lis = "".join([f"<li>{html_escape(str(x))}</li>" for x in items])
    return f"<ul>{lis}</ul>"

# --------------------
# Routes
# --------------------
@APP.get("/", response_class=HTMLResponse)
def home(request: Request):
    cfg = load_config()
    st = load_state()
    day = latest_day_dir()

    html = UI_PATH.read_text(encoding="utf-8")

    badge = '<span class="badge ok">ENABLED</span>' if cfg.get("enabled") else '<span class="badge bad">DISABLED</span>'
    html = html.replace("{{STATUS_BADGE}}", badge)
    html = html.replace("{{MODE}}", html_escape(str(cfg.get("mode"))))
    html = html.replace("{{LAST_POLL}}", html_escape(str(st.get("last_poll_utc"))))
    html = html.replace("{{LAST_ERROR}}", html_escape(str(st.get("last_error"))))

    if not day:
        html = html.replace("{{LATEST_HTML}}", '<div class="panel" style="margin-top:16px;"><h2>No results yet</h2><div class="muted">Turn ON the agent and generate an alert.</div></div>')
        html = html.replace("{{HISTORY_HTML}}", '<div class="muted">No history yet.</div>')
        return HTMLResponse(html)

    entries = load_entries(day, int(cfg.get("show_items", 20)))
    if not entries:
        html = html.replace("{{LATEST_HTML}}", '<div class="panel" style="margin-top:16px;"><h2>No results yet</h2><div class="muted">Turn ON the agent and generate an alert.</div></div>')
        html = html.replace("{{HISTORY_HTML}}", '<div class="muted">No history yet.</div>')
        return HTMLResponse(html)

    latest = entries[0]
    history = entries[1:]
    r = latest["result"]
    sev = sev_class((r.get("priority") or "").lower())

    latest_html = f"""
    <div class="grid">
      <div class="card">
        <div class="meta">
          <b>{html_escape(latest["ts_local"])}</b> <span class="muted">({html_escape(latest["ts_utc"])})</span> |
          rule <b>{html_escape(latest["rule_id"])}</b> | agent <b>{html_escape(latest["agent"])}</b> |
          mode <b>{html_escape(str(latest["meta"].get("mode","")))}</b> | model <b>{html_escape(str(latest["meta"].get("model","")))}</b> |
          elapsed <b>{html_escape(str(latest["meta"].get("elapsed_seconds","")))}s</b>
        </div>

        <div class="row">
          <span class="sev {sev}">Priority: {html_escape(r.get("priority",""))}</span>
          <span class="pill"><span class="muted">Classification</span> <b>{html_escape(r.get("classification",""))}</b></span>
          <span class="pill"><span class="muted">Confidence</span> <b>{html_escape(str(r.get("confidence","")))}</b></span>
        </div>

        <div class="block"><b>Likely issue:</b> {html_escape(r.get("likely_attack_or_issue",""))}</div>

        <div class="kfs">
          <span class="kf">src_ip: <span class="kv">{html_escape(latest["src_ip"] or "-")}</span></span>
          <span class="kf">user: <span class="kv">{html_escape(latest["username"] or "-")}</span></span>
          <span class="kf">path: <span class="kv">{html_escape(latest["path"] or "-")}</span></span>
          <span class="kf">reason: <span class="kv">{html_escape(latest["reason"] or "-")}</span></span>
        </div>

        <div class="cols">
          <div class="panel">
            <h2>Summary</h2>
            {html_ul(r.get("summary", []))}
          </div>
          <div class="panel">
            <h2>Next steps</h2>
            {html_ul(r.get("recommended_next_steps", []))}
          </div>
        </div>

        {f"<div class='err'><b>Error:</b> {html_escape(str(r.get('error')))}</div>" if r.get("error") else ""}

        <details>
          <summary>Show full result JSON</summary>
          <div class="actions">
            <a class="btn" href="#" onclick="copyJson('latest_json'); return false;">Copy JSON</a>
          </div>
          <pre id="latest_json">{html_escape(latest["result_json"])}</pre>
        </details>
      </div>

      <div class="panel">
        <h2>Stream</h2>
        <div class="muted">
          Newest folder: <b>{html_escape(day.name)}</b><br/>
          Showing: <b>{min(int(cfg.get("show_items",20)), len(entries))}</b> items<br/>
          Refresh: every <b>10s</b>
        </div>
      </div>
    </div>
    """

    history_parts = []
    for e in history:
        rr = e["result"]
        sev2 = sev_class((rr.get("priority") or "").lower())
        history_parts.append(f"""
        <details>
          <summary>
            {html_escape(e["ts_local"])} | rule {html_escape(e["rule_id"])} | {html_escape(e["agent"])} |
            <span class="sev {sev2}">{html_escape(rr.get("classification",""))} / {html_escape(rr.get("priority",""))}</span> |
            {html_escape(str(e["meta"].get("mode","")))} ({html_escape(str(e["meta"].get("elapsed_seconds","")))}s)
          </summary>

          <div class="meta">UTC: {html_escape(e["ts_utc"])} | model {html_escape(str(e["meta"].get("model","")))}</div>

          <div class="kfs">
            <span class="kf">src_ip: <span class="kv">{html_escape(e["src_ip"] or "-")}</span></span>
            <span class="kf">user: <span class="kv">{html_escape(e["username"] or "-")}</span></span>
            <span class="kf">path: <span class="kv">{html_escape(e["path"] or "-")}</span></span>
            <span class="kf">reason: <span class="kv">{html_escape(e["reason"] or "-")}</span></span>
          </div>

          <div class="block"><b>Likely issue:</b> {html_escape(rr.get("likely_attack_or_issue",""))}</div>

          <div class="cols">
            <div class="panel">
              <h2>Summary</h2>
              {html_ul(rr.get("summary", []))}
            </div>
            <div class="panel">
              <h2>Next steps</h2>
              {html_ul(rr.get("recommended_next_steps", []))}
            </div>
          </div>

          {f"<div class='err'><b>Error:</b> {html_escape(str(rr.get('error')))}</div>" if rr.get("error") else ""}

          <details>
            <summary>Show JSON</summary>
            <div class="actions">
              <a class="btn" href="#" onclick="copyJson('{html_escape(e["base"])}_json'); return false;">Copy JSON</a>
            </div>
            <pre id="{html_escape(e["base"])}_json">{html_escape(e["result_json"])}</pre>
          </details>
        </details>
        """)

    html = html.replace("{{LATEST_HTML}}", latest_html)
    html = html.replace("{{HISTORY_HTML}}", "\n".join(history_parts) if history_parts else '<div class="muted">No history yet.</div>')
    return HTMLResponse(html)

@APP.get("/agent/on")
def agent_on(msg: str = "Agent enabled"):
    cfg = load_config()
    cfg["enabled"] = True
    save_json(CONFIG_PATH, cfg)
    ensure_worker()

    if cfg.get("start_mode", "now") == "now":
        baseline_seen_ids_now(cfg)

    return RedirectResponse(url=f"/?msg={msg.replace(' ', '%20')}", status_code=303)

@APP.get("/agent/off")
def agent_off(msg: str = "Agent disabled"):
    cfg = load_config()
    cfg["enabled"] = False
    save_json(CONFIG_PATH, cfg)
    return RedirectResponse(url=f"/?msg={msg.replace(' ', '%20')}", status_code=303)

@APP.get("/mode/{mode}")
def set_mode(mode: str, msg: str = ""):
    mode = mode.lower()
    if mode not in ("local", "cloud"):
        return JSONResponse({"ok": False, "error": "mode must be local or cloud"}, status_code=400)

    cfg = load_config()
    cfg["mode"] = mode
    save_json(CONFIG_PATH, cfg)
    ensure_worker()

    toast = msg or f"Mode set to {mode}"
    return RedirectResponse(url=f"/?msg={toast.replace(' ', '%20')}", status_code=303)

@APP.get("/api/status")
def api_status():
    return {"config": load_config(), "state": load_state()}