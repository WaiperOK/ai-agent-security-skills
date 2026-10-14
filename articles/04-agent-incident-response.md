# When Your Agent Gets Hijacked: An Incident Response Playbook

*Agent incidents break the usual forensics habits. The cause is text, the evidence is a transcript, and the thing you are chasing may never reproduce.*

Sooner or later an agent you run will do something it should not have. It calls a tool nobody asked for. It posts a link with a long query string. It quotes something from a document it should not have been reading. Maybe a user reports it, maybe a bug bounty researcher does, maybe you notice a spike in token usage at 3 a.m.

Classic incident response still applies: detect, contain, preserve, investigate, recover, learn. But agent incidents have properties that change how each step works. This post is the playbook behind the [`ai-agent-incident-response`](https://github.com/WaiperOK/ai-agent-security-skills/blob/main/skills/ai-agent-incident-response/SKILL.md) skill, and it assumes you have already read about the [lethal trifecta](01-lethal-trifecta.md), because that is where most of these incidents start.

## What is different about agent incidents

- **The cause is usually text.** An instruction hidden in a document, a web page, a ticket, a log line, or a tool description. By the time you look, the source may have been edited or deleted.
- **The agent acts with real credentials.** Blast radius equals tool permissions, not model capability. A weak model with an admin token is worse than a strong model with a read-only one.
- **Behavior is non-deterministic.** Replaying the same input may produce a different result. One failed reproduction proves almost nothing.
- **Memory persists.** A poisoned note can keep steering later sessions and other users long after the original trigger is gone.
- **Your audit trail is the transcript and the tool-call log.** If you did not record them, you cannot answer "what happened."

That last point is the one teams discover too late. Decide what you log before the incident, not during it.

## Phase 1: Triage in fifteen minutes

Treat these as signals worth a look:

- tool calls the user did not request, or tools unrelated to the task;
- outbound requests to unfamiliar domains, or output containing links and images with long query strings;
- reads of secrets, configuration, or other users' data;
- output that contradicts the visible task, or the agent repeating odd instructions;
- loops, token spikes, or repeated policy denials.

Then answer five questions, because they decide everything else:

1. Did private data leave the trust boundary?
2. Did the agent take irreversible or external actions?
3. Is the trigger still active (a poisoned document, ticket, memory entry, or server)?
4. Which credentials and tools could the agent reach?
5. Is more than one user or tenant affected?

## Phase 2: Contain first, understand later

A leaking agent that keeps running costs more than an incomplete picture. In order:

1. **Stop the agent.** Use the kill switch, disable the deployment, or pause the tools involved.
2. **Cut egress.** Block or allowlist outbound traffic from the agent runtime.
3. **Revoke credentials** the agent could reach. If exfiltration is possible, rotate rather than just disable.
4. **Quarantine the trigger.** Copy the poisoned document, ticket, or server definition as evidence, then isolate it. Do not delete it yet.
5. **Freeze memory.** Snapshot it and stop further writes. Do not wipe it yet.
6. **Disable suspect MCP servers** and block their update channel.

## Phase 3: Preserve evidence before you clean

Capture, read-only and access-limited:

- full transcripts: system prompt, user turns, tool calls **with arguments**, tool results, model output;
- gateway and tool-call logs, including confirmations shown and given, and policy denials;
- model name and version, parameters, prompt template and guardrail versions;
- memory snapshots and RAG index state, with timestamps;
- the suspected trigger, with a hash;
- DNS, proxy, and egress logs for the agent runtime;
- the tool list, permissions, and MCP server versions with their [definition fingerprints](03-audit-an-mcp-server.md).

Transcripts contain secrets and personal data. Redact working copies, never the originals.

## Phase 4: Investigate

Build a timeline, then work backwards from the first deviation.

**Find the trigger.** Search every text source the agent read for instruction-like content: imperatives addressed to the model, invisible characters, odd formatting, references to secrets or tools. A first pass can be mechanical. This is a small scanner for transcripts stored as JSON lines with `role` and `content` fields:

```python
import json
import re
import sys
import unicodedata
from pathlib import Path

PHRASES = re.compile(
    r"ignore (all |any )?(previous|prior|above) (instructions|rules)"
    r"|do not (tell|mention|inform|reveal)[^.]{0,40}\b(user|human|owner)\b"
    r"|you must now|new instructions?:|^\s*system\s*:",
    re.IGNORECASE | re.MULTILINE,
)
URL = re.compile(r"https?://[^\s)\"'>]+", re.IGNORECASE)


def findings(role: str, text: str) -> list[str]:
    out = []
    hidden = sorted({f"U+{ord(c):04X}" for c in text if unicodedata.category(c) in {"Cf", "Co", "Cn"}})
    if hidden:
        out.append("invisible characters: " + ", ".join(hidden[:6]))
    for m in PHRASES.finditer(text):
        out.append(f"instruction-like text: {m.group(0).strip()[:60]!r}")
    if role in {"assistant", "tool_call"}:
        for url in URL.findall(text):
            if len(url) > 120 or "?" in url and len(url.split("?", 1)[1]) > 40:
                out.append(f"long URL in model output: {url[:70]}...")
    return out


def scan(path: Path) -> int:
    hits = 0
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        for f in findings(str(row.get("role", "")), str(row.get("content", ""))):
            print(f"line {n} [{row.get('role')}]: {f}")
            hits += 1
    return hits


if __name__ == "__main__":
    sys.exit(1 if scan(Path(sys.argv[1])) else 0)
```

Run `python scan_transcript.py transcript.jsonl`. It flags invisible characters, a few common instruction phrasings in data, and long URLs in model output that could carry encoded data. It exits non-zero when it finds something, so you can use it in a pipeline.

Be honest about what this is. It is a **triage heuristic**, not a detector. An attacker who avoids the phrases it knows will pass it, and a clean result proves nothing. Its job is to get you to the suspicious lines faster so you can read them yourself.

**Trace the path.** From trigger, to first deviation, to each tool call, to data leaving. Name the trust boundary that failed.

**Establish impact by what happened, not by what the model "intended."** Check actual egress records. List every state-changing action with its target and time. Check whether the incident reached memory, other sessions, or other users.

**State the root cause architecturally.** Typical answers are: untrusted content and private data in one context; an over-privileged token; no egress control; no confirmation on a risky action; an unpinned or malicious tool definition; unvalidated memory writes. "The model was tricked" is a description of the trigger, not a root cause.

**Check for recurrence.** Search other transcripts and sources for the same trigger text.

**Reproduce carefully, or not at all.** Use an isolated environment with test credentials and canary data, run the scenario several times, and record the success rate. Do not reproduce against production data to prove a point.

## Phase 5: Recover

- Remove or sanitize the trigger at its source, after the evidence is saved.
- Clean memory: remove poisoned entries, review everything written during the incident window, and restore from a known-good snapshot if you have one.
- Rotate any secret that appeared in context or logs.
- **Restart only after the fix is in place**, not before.
- Roll back or compensate for irreversible actions: restore data, recall messages, revert commits, notify affected parties.
- Watch closely after restart, with alerts on the original trigger pattern and on related tool calls and egress.

## Phase 6: Fix the cause, then prove it

Every incident should end in an architectural control and a test. A better system prompt is not a fix.

| Root cause | Control |
|---|---|
| All three trifecta legs present | Remove one, split the agent, or require human approval |
| Over-privileged tools | Least privilege, scoped short-lived tokens, read-only by default |
| Data left through links or requests | Egress allowlist; no auto-rendered external images or links |
| Risky action ran unattended | Confirmation with exact arguments; rate and amount limits |
| Malicious or changed tool definition | Pinning, fingerprint checks, re-approval on change |
| Poisoned memory | Controlled writes, per-user isolation, audit, rollback |
| No visibility | Full tool-call logging, alerts, kill switch |

Then write a regression test that replays the trigger against the fixed system and asserts the control holds. If you cannot test it, you do not know it is fixed.

## Communicating during the incident

Keep one owner and one timeline. Update stakeholders on a fixed cadence and say what is known, what is not, and when the next update comes. Bring legal and privacy teams in early if personal or regulated data may have left, because notification duties depend on jurisdiction and contracts. If a third-party product is involved, report through its security contact with evidence and follow coordinated disclosure.

## A blameless postmortem has five parts

Summary and impact; a timeline with sources; the trigger and the architectural root cause; what went well and what did not (detection, containment speed, log quality); and actions, each with an owner, a due date, and the test that verifies it. Feed the results back into your [threat model](https://github.com/WaiperOK/ai-agent-security-skills/blob/main/skills/ai-agent-threat-modeling/SKILL.md) so the next review starts from what you learned.

## Takeaways

1. Decide what to log before an incident: transcripts and tool calls with arguments are your evidence.
2. Contain first. Stopping a leaking agent beats a complete explanation.
3. Preserve before you clean. Transcripts and memory snapshots cannot be recreated.
4. Judge impact by what the agent reached and actually sent.
5. Every incident ends with an architectural fix and a regression test.

The full checklist, containment order, and postmortem template are in the [`ai-agent-incident-response`](https://github.com/WaiperOK/ai-agent-security-skills/blob/main/skills/ai-agent-incident-response/SKILL.md) skill.

## References

- Simon Willison, ["The lethal trifecta for AI agents"](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/): LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM06 Excessive Agency
- [MITRE ATLAS](https://atlas.mitre.org/)
