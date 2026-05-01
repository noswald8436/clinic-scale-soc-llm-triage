#!/usr/bin/env python3
import json
import time
from pathlib import Path
from datetime import datetime, timezone

BUNDLES_DIR = Path("/opt/capstone/03-cases/bundles")
OUT_DIR = Path("/opt/capstone/05-triage-assistant/outputs/manual")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def now_utc():
    return datetime.now(timezone.utc).isoformat()

def md_escape(s: str) -> str:
    return s.replace("\n", " ").strip()

def triage_note(bundle: dict) -> str:
    alert = bundle.get("alert", {})
    key = bundle.get("key_fields", {}) or bundle.get("entities", {})
    return f"""# Triage Note (Manual Baseline)

## Case
- case_id: `{bundle.get("case_id","")}`
- scenario_label: `{bundle.get("scenario_label","")}`
- truth_classification: `{bundle.get("truth_classification","")}`

## Alert
- timestamp: `{alert.get("timestamp", alert.get("timestamp_utc",""))}`
- rule: `{alert.get("rule_id","")}` (level {alert.get("rule_level","")}) — {md_escape(str(alert.get("rule_description","")))}
- agent: `{alert.get("agent_name","")}` ({alert.get("agent_ip","")})
- location: `{alert.get("location","")}`

## Key fields
- src_ip: `{key.get("src_ip", key.get("client_ip",""))}`
- username: `{key.get("username","")}`
- path: `{key.get("path", key.get("http_path",""))}`
- reason/status: `{key.get("reason", key.get("status_code",""))}`

## Analyst summary (fill in)
- What happened:
- Why it matters:
- Priority (low/medium/high):
- Recommended next steps (3–5):
"""

def main():
    bundles = sorted(BUNDLES_DIR.glob("*.json"))
    if not bundles:
        print(f"No bundles found in {BUNDLES_DIR}")
        return

    for p in bundles:
        t0 = time.time()
        bundle = json.loads(p.read_text(encoding="utf-8"))

        md = triage_note(bundle)

        out_base = OUT_DIR / p.stem
        md_path = Path(str(out_base) + ".md")
        meta_path = Path(str(out_base) + ".meta.json")

        md_path.write_text(md, encoding="utf-8")

        meta = {
            "case_file": str(p),
            "generated_utc": now_utc(),
            "mode": "manual_template",
            "elapsed_seconds": round(time.time() - t0, 4)
        }
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

        print(f"Wrote: {md_path} and {meta_path}")

if __name__ == "__main__":
    main()
