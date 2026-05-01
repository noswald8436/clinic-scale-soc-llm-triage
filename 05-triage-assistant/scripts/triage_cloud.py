#!/usr/bin/env python3
import os, json, time
from pathlib import Path
from datetime import datetime, timezone
from openai import OpenAI

BUNDLES_DIR = Path("/opt/capstone/03-cases/bundles")
PROMPT_PATH = Path("/opt/capstone/05-triage-assistant/prompts/prompt_v1.txt")
OUT_DIR = Path("/opt/capstone/05-triage-assistant/outputs/cloud")
OUT_DIR.mkdir(parents=True, exist_ok=True)

MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")  # cost-effective + good for structured output

def now_utc():
    return datetime.now(timezone.utc).isoformat()

def load_prompt():
    return PROMPT_PATH.read_text(encoding="utf-8")

def to_markdown(case_id: str, result: dict) -> str:
    bullets = "\n".join([f"- {b}" for b in result.get("summary", [])])
    steps = "\n".join([f"- {s}" for s in result.get("recommended_next_steps", [])])
    return f"""# Cloud LLM Triage

- case_id: `{case_id}`
- classification: **{result.get('classification','')}**
- priority: **{result.get('priority','')}**
- confidence: `{result.get('confidence','')}`
- likely_attack_or_issue: {result.get('likely_attack_or_issue','')}

## Summary
{bullets}

## Recommended next steps
{steps}
"""

def main():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("OPENAI_API_KEY not set in environment.")

    bundles = sorted(BUNDLES_DIR.glob("*.json"))
    if not bundles:
        raise SystemExit(f"No bundles found in {BUNDLES_DIR}")

    prompt_header = load_prompt()
    client = OpenAI()

    for p in bundles:
        bundle = json.loads(p.read_text(encoding="utf-8"))
        case_id = bundle.get("case_id", p.stem)

        user_content = prompt_header + "\n" + json.dumps(bundle, indent=2)

        t0 = time.time()
        resp = client.responses.create(
            model=MODEL,
            input=user_content,
            text={"format": {"type": "json_object"}}
        )
        elapsed = time.time() - t0

        # Responses API returns text in output_text
        text = resp.output_text.strip()

        # Parse JSON output
        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            # Save raw if model returns non-JSON
            raw_path = OUT_DIR / f"{case_id}.raw.txt"
            raw_path.write_text(text, encoding="utf-8")
            raise SystemExit(f"Model did not return valid JSON for {case_id}. Raw saved to {raw_path}")

        # Write structured output
        out_json = OUT_DIR / f"{case_id}.cloud.json"
        out_md = OUT_DIR / f"{case_id}.cloud.md"
        meta = {
            "case_id": case_id,
            "source_bundle": str(p),
            "generated_utc": now_utc(),
            "model": MODEL,
            "elapsed_seconds": round(elapsed, 4)
        }
        out_meta = OUT_DIR / f"{case_id}.cloud.meta.json"

        out_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
        out_md.write_text(to_markdown(case_id, result), encoding="utf-8")
        out_meta.write_text(json.dumps(meta, indent=2), encoding="utf-8")

        print(f"[OK] {case_id} -> {out_json.name} ({meta['elapsed_seconds']}s)")

if __name__ == "__main__":
    main()
