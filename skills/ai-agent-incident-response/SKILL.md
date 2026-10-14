---
name: ai-agent-incident-response
description: Incident response playbook for a suspected compromise or misbehavior of an AI agent or LLM application - prompt injection, data exfiltration, unauthorized tool calls, poisoned memory, malicious MCP server. Covers triage, containment, evidence preservation, transcript forensics, credential rotation, memory cleanup, recovery, and a blameless postmortem. Use when an agent did something it should not have, when a leak or injection is suspected, or when preparing an agent incident runbook. Triggers - AI agent incident, prompt injection incident, agent compromised, agent leaked data, agent IR runbook.
---

# AI Agent Incident Response

A playbook for incidents where an agent (LLM + tools + memory + external data) is the victim, the vehicle, or the leak path.
Work only on systems you are authorized to investigate. Handle transcripts as sensitive data: they may contain secrets and personal data.

## What makes agent incidents different

- The **cause is often text**: an injected instruction in a document, web page, ticket, log line, or tool description. The trigger may be long gone from the source by the time you look.
- The agent acts with **real credentials**. Impact equals tool permissions, not model capability.
- Behavior is **non-deterministic**. Replaying the same input may not reproduce the incident.
- **Memory persists**. A poisoned note can keep affecting later sessions and other users.
- The audit trail is the **transcript and tool-call log**. If you do not have it, you cannot answer what happened.

## 1. Detect and triage (first 15 minutes)

Signals worth treating as incidents:
- tool calls the user did not request, or to tools unrelated to the task;
- outbound requests to unknown domains, links or images with long query strings in output;
- unexpected reads of secrets, configuration, or other users' data;
- the agent repeating odd instructions, or output that contradicts the visible task;
- sudden spikes in token use, loops, or repeated policy denials;
- a report from a user, vendor, or bug bounty researcher.

Classify quickly:

| Question | Why |
|---|---|
| Did private data leave the trust boundary? | Decides breach handling and notification duties |
| Did the agent take irreversible or external actions? | Decides rollback work |
| Is the trigger still active (poisoned doc, ticket, memory, server)? | Decides whether containment can wait |
| Which credentials and tools were reachable? | Defines blast radius |
| Is more than one user or tenant affected? | Defines scope |

Assign a severity (see the risk rating in the ai-agent-threat-modeling skill) and an incident owner.

## 2. Contain

Do these first; investigate after.

1. **Stop the agent**: kill switch, disable the deployment, or pause the specific tools involved.
2. **Cut egress**: block outbound traffic from the agent runtime or restrict it to an allowlist.
3. **Revoke credentials** the agent could reach: API keys, OAuth tokens, service accounts, database users. Rotate rather than only disable if exfiltration is possible.
4. **Isolate the trigger**: quarantine the poisoned document, ticket, web source, or MCP server. Do not delete it yet; copy it as evidence.
5. **Freeze memory**: snapshot long-term memory and stop further writes. Do not wipe it yet.
6. **Disable suspect MCP servers or plugins** and block their update channel.

## 3. Preserve evidence

Before cleaning anything, capture:
- full transcripts (system prompt, user turns, tool calls with arguments, tool results, model outputs);
- tool-call and gateway logs, confirmations shown and given, policy denials;
- model and provider details: model name and version, parameters, prompt template versions, guardrail versions;
- memory snapshots and RAG index state, with timestamps;
- the suspected trigger artifact (document, page, ticket, tool definition) with its hash;
- network logs: DNS, proxy, and egress records for the agent runtime;
- configuration: tool list, permissions, MCP server versions and definition fingerprints.

Store evidence read-only, with access limited to the response team. Redact secrets in working copies, not in the originals.

## 4. Investigate

Build a timeline from the transcript and logs.

1. **Find the trigger.** Search context sources for instruction-like text: imperatives addressed to the model, hidden or invisible characters, odd formatting, references to tools or secrets.
2. **Trace the path.** From trigger to first deviation, to each tool call, to data leaving. Note which trust boundary failed.
3. **Establish impact.**
   - What data did the agent read, and what could it send? Check actual egress, not only intent.
   - Which actions changed state? List each with target and time.
   - Did the incident reach memory, other sessions, or other users?
4. **Identify the root cause in architectural terms.** Typical answers: untrusted content and private data in one context, an over-privileged token, no egress control, no confirmation on a risky action, an unpinned or malicious tool definition, unvalidated memory writes.
5. **Check for recurrence.** Search other transcripts and sources for the same trigger text or pattern.

Reproduce carefully: run in an isolated environment with test credentials and canary data. Record success rate across repeated runs, since a single failure to reproduce proves little.

## 5. Eradicate and recover

- Remove or sanitize the trigger in its source, after evidence is saved.
- Clean memory: remove poisoned entries, restore from a known-good snapshot, and review entries written during the incident window.
- Rotate remaining secrets that appeared in context or logs.
- Restore the agent with the fixes from section 6 in place, not before.
- Roll back or compensate for irreversible actions: restore data, recall messages, revert commits, notify affected parties.
- Monitor closely after restart: alert on the original trigger pattern and on related tool calls and egress.

## 6. Fix the cause

Map each root cause to an architectural control (see the ai-agent-defense skill):

| Root cause | Control |
|---|---|
| Trifecta present | Remove a leg, split agents, or require human approval |
| Over-privileged tools | Least privilege, scoped short-lived tokens, read-only default |
| Data left through links or requests | Egress allowlist, no auto-rendered external images or links |
| Risky action ran unattended | Confirmation with exact arguments, rate and amount limits |
| Malicious or changed tool definition | Pinning, fingerprint checks, re-approval on change (see mcp-server-audit) |
| Poisoned memory | Controlled writes, per-user isolation, audit, rollback |
| No visibility | Full tool-call logging, alerts, kill switch |

Add a regression test from the ai-agent-redteam skill that replays the trigger and asserts the control holds.

## 7. Communicate

- Keep a single timeline and a single owner. Update stakeholders on a fixed cadence.
- Say what is known, what is not, and when the next update comes.
- Involve legal and privacy teams early if personal or regulated data may have left. Notification duties depend on jurisdiction and contracts.
- If a third-party product or vendor is involved, report it through their security contact with evidence, and follow coordinated disclosure.

## 8. Blameless postmortem template

```markdown
# Postmortem: <short title>
Date: YYYY-MM-DD | Severity: ... | Owner: ...

## Summary
What happened, impact, duration.

## Timeline
Time, event, source (transcript, log, report).

## Trigger and root cause
Trigger artifact, failed trust boundary, architectural cause.

## Impact
Data exposed, actions taken, users and tenants affected.

## What went well / what did not
Detection, containment speed, logging quality.

## Actions
| Action | Control | Owner | Due | Verified by test |
|--------|---------|-------|-----|------------------|

## Lessons for the threat model
Updates to the threat register and trust boundaries.
```

## Principles

- Contain first, then understand. Delay in stopping a leaking agent costs more than an incomplete picture.
- Preserve before you clean: transcripts and memory are your evidence.
- Judge impact by what the agent could reach and actually sent, not by what the model "intended".
- Every incident ends in an architectural control and a regression test, not only a better prompt.
