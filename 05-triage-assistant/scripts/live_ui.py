from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pathlib import Path
import json

APP = FastAPI()

OUT_ROOT = Path("/opt/capstone/05-triage-assistant/outputs/live")
CONFIG_PATH = Path("/opt/capstone/05-triage-assistant/live_config.json")

def latest_day_dir():
    days = sorted([p for p in OUT_ROOT.glob("*") if p.is_dir()])
    return days[-1] if days else None

def load_config():
    if not CONFIG_PATH.exists():
        return {"mode": "local"}
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

def save_config(cfg):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

@APP.get("/", response_class=HTMLResponse)
def home():
    cfg = load_config()
    mode = cfg.get("mode", "local")

    html = f"""
    <html>
    <head>
      <title>Live AI Analyst</title>
      <meta http-equiv="refresh" content="5">
      <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .row {{ display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }}
        .pill {{ display:inline-block; padding:2px 10px; border-radius: 12px; background:#eef; }}
        .card {{ border: 1px solid #ddd; padding: 12px; margin: 10px 0; border-radius: 8px; }}
        .meta {{ color: #555; font-size: 0.9em; margin-bottom: 6px; }}
        pre {{ background: #f7f7f7; padding: 10px; border-radius: 6px; overflow-x: auto; }}
        a.button {{
          display:inline-block; padding:6px 10px; border:1px solid #888; border-radius:6px;
          text-decoration:none; color:#111; background:#fafafa;
        }}
      </style>
    </head>
    <body>
      <h1>Live AI Analyst</h1>

      <div class="row">
        <div><b>Mode:</b> <span class="pill">{mode}</span></div>
        <div>
          <a class="button" href="/set_mode/local">Switch to Local</a>
          <a class="button" href="/set_mode/cloud">Switch to Cloud</a>
        </div>
      </div>

      <p class="meta">Auto-refresh: every 5 seconds. Outputs are read from the latest dated folder.</p>

      <h2>Latest triage results</h2>
    """

    day = latest_day_dir()
    if not day:
        return html + "<p>No live output yet.</p></body></html>"

    metas = sorted(day.glob("live_*.meta.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:10]

    for m in metas:
        meta = json.loads(m.read_text(encoding="utf-8"))
        base = m.name.replace(".meta.json", "")
        bundle_path = day / f"{base}.bundle.json"
        mode_from_meta = meta.get("mode", "local")
        result_path = day / f"{base}.{mode_from_meta}.json"


        bundle = json.loads(bundle_path.read_text(encoding="utf-8")) if bundle_path.exists() else {}
        result = json.loads(result_path.read_text(encoding="utf-8")) if result_path.exists() else {}

        alert = bundle.get("alert", {})
        rule_id = alert.get("rule_id", "")
        agent = alert.get("agent_name", "")
        ts = alert.get("timestamp", "")

        html += f"""
        <div class="card">
          <div class="meta">
            <b>{ts}</b> | rule <b>{rule_id}</b> | agent <b>{agent}</b> |
            mode <b>{meta.get("mode","")}</b> | model <b>{meta.get("model","")}</b> |
            elapsed <b>{meta.get("elapsed_seconds","")}s</b>
          </div>
          <div>
            <b>Classification:</b> {result.get("classification","")} |
            <b>Priority:</b> {result.get("priority","")} |
            <b>Confidence:</b> {result.get("confidence","")}
          </div>
          <div><b>Likely issue:</b> {result.get("likely_attack_or_issue","")}</div>
          <details>
            <summary>Show result JSON</summary>
            <pre>{json.dumps(result, indent=2)}</pre>
          </details>
        </div>
        """

    html += "</body></html>"
    return html

@APP.get("/set_mode/{mode}")
def set_mode(mode: str):
    mode = mode.lower()
    if mode not in ("local", "cloud"):
        return JSONResponse({"ok": False, "error": "mode must be local or cloud"}, status_code=400)

    cfg = load_config()
    cfg["mode"] = mode
    save_config(cfg)

    # Redirect back to the UI
    return RedirectResponse(url="/", status_code=303)

@APP.get("/api/config")
def api_config():
    return load_config()