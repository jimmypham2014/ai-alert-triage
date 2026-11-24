"""
AI Alert Triage Assistant - starter version
Reads security alerts (Wazuh-style JSON lines), asks an LLM to triage each one,
and writes results to a CSV for review.

Usage:
  python triage.py sample_alerts.json --dry-run     # see the prompt, no API call
  python triage.py sample_alerts.json               # real run (needs ANTHROPIC_API_KEY)
"""
import argparse
import csv
import json
import os
import sys

MODEL = os.environ.get("TRIAGE_MODEL", "claude-sonnet-5-5")

SYSTEM_PROMPT = """You are a senior SOC analyst. Triage the security alert you are given.
Respond with ONLY a JSON object with these keys:
  "verdict": one of "true_positive", "benign", "needs_investigation"
  "severity": one of "low", "medium", "high", "critical"
  "mitre_technique": ATT&CK technique ID and name, e.g. "T1059.001 PowerShell", or "none"
  "summary": one or two plain-English sentences on what happened
  "next_steps": a list of up to 3 concrete investigation or response actions
  "confidence": a number from 0 to 1
Base your answer only on the alert data. If the data is insufficient, say so and use "needs_investigation"."""


def load_alerts(path):
    """Accepts any of:
    - a single alert pasted from the Wazuh dashboard's JSON tab
    - a JSON array of alerts
    - JSON lines (one alert per line, like Wazuh's alerts.json)
    """
    # Windows tools may save as UTF-8 (with or without a BOM) or UTF-16
    raw = open(path, "rb").read()
    encoding = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
    text = raw.decode(encoding).strip()
    try:
        data = json.loads(text)
        alerts = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        alerts = [json.loads(line) for line in text.splitlines() if line.strip()]
    # Dashboard exports wrap the alert in "_source"; unwrap it
    return [a.get("_source", a) for a in alerts]


def slim_alert(alert):
    """Keep only the fields the model needs - cuts cost and noise."""
    rule = alert.get("rule", {})
    return {
        "timestamp": alert.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_description": rule.get("description"),
        "rule_level": rule.get("level"),
        "agent": alert.get("agent", {}).get("name"),
        "data": alert.get("data", {}),
        "full_log": (alert.get("full_log") or "")[:2000],
    }


def triage(client, alert):
    msg = client.messages.create(
        model=MODEL,
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": json.dumps(slim_alert(alert), indent=2)}],
    )
    # The reply can contain several blocks (e.g. a "thinking" block before the
    # answer on complex alerts), so collect only the text blocks.
    text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
    # Pull out just the JSON object, even if the model adds extra text around it
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"No JSON in reply: {text[:300]}")
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        raise ValueError(f"Bad JSON in reply: {text[:300]}")


def format_steps(steps):
    """Join next_steps for the CSV. The model is asked for a list, but may
    return a single string; joining a string would split it into characters."""
    if not steps:
        return ""
    if isinstance(steps, str):
        return steps
    return " | ".join(str(s) for s in steps)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("alerts_file")
    p.add_argument("--out", default="triage_results.csv")
    p.add_argument("--dry-run", action="store_true", help="print prompts, skip API")
    args = p.parse_args()

    alerts = load_alerts(args.alerts_file)
    print(f"Loaded {len(alerts)} alerts")

    if args.dry_run:
        for a in alerts:
            print("-" * 60)
            print(json.dumps(slim_alert(a), indent=2))
        return

    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("Set ANTHROPIC_API_KEY first (or use --dry-run).")
    import anthropic  # pip install anthropic
    client = anthropic.Anthropic()

    fields = ["timestamp", "rule_description", "verdict", "severity",
              "mitre_technique", "confidence", "summary", "next_steps",
              "analyst_verdict"]  # you fill analyst_verdict in to score accuracy
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for i, a in enumerate(alerts, 1):
            try:
                r = triage(client, a)
            except Exception as e:
                r = {"verdict": "error", "summary": str(e)}
            w.writerow({
                "timestamp": a.get("timestamp"),
                "rule_description": a.get("rule", {}).get("description"),
                "verdict": r.get("verdict"),
                "severity": r.get("severity"),
                "mitre_technique": r.get("mitre_technique"),
                "confidence": r.get("confidence"),
                "summary": r.get("summary"),
                "next_steps": format_steps(r.get("next_steps")),
                "analyst_verdict": "",
            })
            print(f"[{i}/{len(alerts)}] {r.get('verdict')} - {a.get('rule', {}).get('description')}")
    print(f"Results written to {args.out}")


if __name__ == "__main__":
    main()
