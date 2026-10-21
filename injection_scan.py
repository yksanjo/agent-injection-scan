"""Offline prompt-injection pattern scanner for agent traces.

Agents ingest untrusted text: web pages, emails, documents, tool results.
Some of that text tries to instruct the agent - override its goals, exfiltrate
data, claim authority, or hide itself. This tool scans a recorded JSONL trace
for those patterns and reports findings. It is a heuristic scanner, not a
firewall: it never runs an agent, never calls a model, and cannot block
anything.

Exit code is 1 when any finding has severity "error", else 0.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    code: str
    severity: str  # error | warning | info
    pattern: re.Pattern[str]
    note: str


DEFAULT_RULES: tuple[Rule, ...] = (
    Rule("override-instruction", "error",
         re.compile(r"\b(ignore|disregard|forget)\s+(all\s+|any\s+|every\s+)?(previous|prior|above|earlier|your)\s+(instructions?|rules?|prompts?)\b", re.I),
         "text tells the reader to discard its standing instructions"),
    Rule("override-instruction", "error",
         re.compile(r"\byou are now\b|\bact as\b.{0,40}\b(no restrictions|without (any )?(restrictions|limits|rules)|unrestricted)\b|\bnew (system )?instructions?:", re.I),
         "text tries to reassign the reader's role or hand it new instructions"),
    Rule("prompt-extraction", "error",
         re.compile(r"\b(reveal|print|show|repeat|output|leak)\b.{0,40}\b(system prompt|initial prompt|your instructions|hidden prompt)\b", re.I),
         "text asks the reader to disclose its own instructions"),
    Rule("exfiltration", "error",
         re.compile(r"\b(send|forward|email|upload|post|transmit)\b.{0,80}\b(to|at)\s+(https?://\S+|[\w.+-]+@[\w-]+\.[\w.]+)", re.I),
         "text asks for data to be sent to an external address"),
    Rule("exfiltration", "error",
         re.compile(r"\b(curl|wget|invoke-webrequest)\b[^|\n]{0,120}(\||>\s*)\s*(bash|sh|python|powershell)\b", re.I),
         "text pipes a remote download straight into an interpreter"),
    Rule("concealment", "warning",
         re.compile(r"\b(do not|don't)\s+(mention|tell|inform|show|reveal)\b.{0,50}\b(user|human|operator|anyone)\b|\bkeep this (secret|hidden|quiet)\b|\bomit this\b", re.I),
         "text asks for its presence or actions to be concealed"),
    Rule("authority-claim", "warning",
         re.compile(r"\b(the user (has )?(already )?(approved|authorized|confirmed)|this (is|was) (approved|authorized)|i am (the|your) (admin|administrator|developer|owner|operator))\b", re.I),
         "text claims authority or prior approval, which it cannot grant itself"),
    Rule("encoded-payload", "warning",
         re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b"),
         "long base64-looking blob; encoded content hides from review"),
    Rule("urgency-pressure", "info",
         re.compile(r"\b(urgent|immediately|right now|do not delay|before it'?s too late)\b.{0,80}\b(send|transfer|pay|delete|post|share|forward)\b", re.I | re.S),
         "urgency paired with an action request is a common pressure tactic"),
)


@dataclass
class Finding:
    code: str
    severity: str
    line: int
    note: str
    snippet: str


def _snippet(text: str, match: re.Match[str], width: int = 60) -> str:
    start = max(0, match.start() - 10)
    end = min(len(text), match.end() + 10)
    frag = " ".join(text[start:end].split())
    if len(frag) > width:
        frag = frag[: width - 1] + "..."
    return frag


def scan_record(rec: dict, line: int, rules: tuple[Rule, ...]) -> list[Finding]:
    """Scan one parsed trace record. Any string field named text/content/body is scanned."""
    findings: list[Finding] = []
    for key in ("text", "content", "body"):
        val = rec.get(key)
        if not isinstance(val, str) or not val:
            continue
        for rule in rules:
            m = rule.pattern.search(val)
            if m:
                findings.append(Finding(rule.code, rule.severity, line, rule.note, _snippet(val, m)))
    return findings


def scan_text(text: str, rules: tuple[Rule, ...] = DEFAULT_RULES) -> list[Finding]:
    """Scan a whole JSONL trace string."""
    findings: list[Finding] = []
    for n, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            findings.append(Finding("bad-record", "error", n, "line is not valid JSON", ""))
            continue
        if not isinstance(rec, dict):
            findings.append(Finding("bad-record", "error", n, "record is not a JSON object", ""))
            continue
        if not any(isinstance(rec.get(k), str) and rec.get(k) for k in ("text", "content", "body")):
            findings.append(Finding("no-text", "info", n, "record has no text/content/body field to scan", ""))
            continue
        findings.extend(scan_record(rec, n, rules))
    return findings


def format_findings(findings: list[Finding]) -> str:
    if not findings:
        return "ok: no injection patterns found"
    order = {"error": 0, "warning": 1, "info": 2}
    out = []
    for f in sorted(findings, key=lambda f: (order.get(f.severity, 3), f.line, f.code)):
        snip = f' - "{f.snippet}"' if f.snippet else ""
        out.append(f"{f.severity}: {f.code}: {f.note} (line {f.line}){snip}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Offline prompt-injection pattern scanner for agent traces.")
    p.add_argument("trace", help="path to a JSONL trace, or '-' for stdin")
    p.add_argument("--min-severity", default="info", choices=("info", "warning", "error"),
                   help="only report findings at this severity or higher")
    args = p.parse_args(argv)
    text = sys.stdin.read() if args.trace == "-" else open(args.trace, encoding="utf-8").read()
    rank = {"info": 0, "warning": 1, "error": 2}
    findings = [f for f in scan_text(text) if rank[f.severity] >= rank[args.min_severity]]
    print(format_findings(findings))
    return 1 if any(f.severity == "error" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
