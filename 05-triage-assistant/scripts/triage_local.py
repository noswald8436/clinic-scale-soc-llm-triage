#!/usr/bin/env python3
import json, os, time, requests
from pathlib import Path
from datetime import datetime, timezone

BUNDLES_DIR = Path("/opt/capstone/03-cases/bundles")
PROMPT_PATH = Path("/opt/capstone/05-triage-assistant/prompts/prompt_v1.txt")
OUT_DIR = Path("/opt/capstone/05-triage-assistant/outputs/local")
OUT_DIR.mkdir(parents=True, exist_ok=True)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://10.10.10.120:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral:7b-instruct")

def now_utc():
    return datetime.now(timezone.utc).isoformat()

def load_prompt():
    return PROMPT_PATH.read_text(encoding="utf-8")

def to_markdown(case_id: str, result: dict) -> str:
    bullets = "\n".join([f"- {b}" for b in result.get("summary", [])])
    steps = "\n".join([f"- {s}" for s in result.get("recommended_next_steps", [])])
    return f"""# Local LLM Triage (Ollama)

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

def ollama_generate(prompt: str) -> str:
    url = f"{OLLAMA_HOST}/api/generate"
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2}
    }
    r = requests.post(url, json=payload, timeout=240)
    r.raise_for_status()
    return r.json().get("response", "").strip()

def main():
    bundles = sorted(BUNDLES_DIR.glob("*.json"))
    if not bundles:
        raise SystemExit(f"No bundles found in {BUNDLES_DIR}")

    prompt_header = load_prompt()

    for p in bundles:
        bundle = json.loads(p.read_text(encoding="utf-8"))
        case_id = bundle.get("case_id", p.stem)

        full_prompt = prompt_header + "\n" + json.dumps(bundle, indent=2)

        t0 = time.time()
        text = ollama_generate(full_prompt)
        elapsed = time.time() - t0

        # Parse JSON; if it fails, save raw and stop
        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            raw_path = OUT_DIR / f"{case_id}.raw.txt"
            raw_path.write_text(text, encoding="utf-8")
            raise SystemExit(f"Ollama did not return valid JSON for {case_id}. Raw saved to {raw_path}")

        out_json = OUT_DIR / f"{case_id}.local.json"
        out_md = OUT_DIR / f"{case_id}.local.md"
        out_meta = OUT_DIR / f"{case_id}.local.meta.json"

        meta = {
            "case_id": case_id,
            "source_bundle": str(p),
            "generated_utc": now_utc(),
            "ollama_host": OLLAMA_HOST,
            "model": OLLAMA_MODEL,
            "elapsed_seconds": round(elapsed, 4)
        }

        out_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
        out_md.write_text(to_markdown(case_id, result), encoding="utf-8")
        out_meta.write_text(json.dumps(meta, indent=2), encoding="utf-8")

        print(f"[OK] {case_id} -> {out_json.name} ({meta['elapsed_seconds']}s)")

if __name__ == "__main__":
    main()
