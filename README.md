# agent-injection-scan

Offline prompt-injection pattern scanner for agent traces.

Agents ingest untrusted text: web pages, emails, documents, tool results. Some of that text tries to instruct the agent - override its goals, exfiltrate data, claim authority it cannot have, or hide itself from the user. This tool scans a recorded trace for those patterns and reports findings with line numbers. It never runs an agent, never calls a model, and cannot block anything. It is a heuristic scanner, not a firewall.

## Trace format

One JSON object per line. Any record carrying a non-empty `text`, `content`, or `body` string field is scanned; other fields are carried by your format and ignored.

```jsonl
{"type": "result", "id": "r1", "tool": "web.fetch", "text": "Page body goes here."}
```

## What it reports

| Code | Severity | Pattern family |
| --- | --- | --- |
| `override-instruction` | error | "ignore previous instructions", role reassignment, "new instructions:" |
| `prompt-extraction` | error | asks the reader to reveal its system prompt or hidden instructions |
| `exfiltration` | error | asks for data to be sent to an external URL/email, or pipes a download into an interpreter |
| `concealment` | warning | asks for its presence or actions to be hidden from the user |
| `authority-claim` | warning | claims prior user approval or admin/developer identity, which text cannot grant itself |
| `encoded-payload` | warning | long base64-looking blob that hides content from review |
| `urgency-pressure` | info | urgency language paired with an action request |
| `bad-record` | error | malformed trace line |
| `no-text` | info | record has no text/content/body field to scan |

## Usage

```bash
python3 injection_scan.py trace.jsonl
cat trace.jsonl | python3 injection_scan.py -
python3 injection_scan.py trace.jsonl --min-severity warning
python3 demo.py
python3 -m unittest test_injection_scan
```

Exit code is 1 when any finding is an error, else 0.

## Honest limits

- Regex heuristics. They produce false positives (a security blog post about injection will match) and false negatives (paraphrased, translated, or encoded attacks slip through). A clean result is not a guarantee of safety.
- Pattern matching cannot tell whether flagged text would actually influence a model; it only reports that the pattern is present in the record.
- Base64 detection flags any long encoded-looking run, including benign embedded assets.
- Scanning happens after the fact, on a recorded trace. This tool cannot intercept or block content before an agent sees it.
- Demo traces are synthetic and invented.

## License

MIT
