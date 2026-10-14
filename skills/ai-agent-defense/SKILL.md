---
name: ai-agent-defense
description: Designing and reviewing defenses for AI agents (blue team) - least privilege, trust boundaries, isolation of untrusted content, human-in-the-loop, egress control, MCP server security, logging and monitoring. Use when building an agent, reviewing its architecture, choosing guardrails, or producing a security checklist. Triggers - secure AI agent, harden LLM app, MCP hardening, agent guardrails, prompt injection mitigation.
---

# AI Agent Defense

Principles and a checklist for defending agents (LLM + tools + memory + external data).

## The core idea

**You cannot reliably "convince" a model to ignore an injection.** Prompt injection remains unsolved at the model level.
So defense is built **around** the model: limit what it can do and what can leak, even if the model is fully compromised.

Mental model: *any untrusted text in the context is code an attacker can run with the agent's privileges.*

## 1. Core principles

1. **Assume the model is compromised.** Design so the worst outcome is acceptable.
2. **Least privilege for tools.** Only the tools that are needed, minimal token scopes, read-only by default.
3. **Break the lethal trifecta.** Never give one agent private data, untrusted content, and external communication at the same time. Remove at least one leg.
4. **Separate trust levels.** Instructions from the owner and data from the outside world are different channels with different trust.
5. **Defense in depth.** Guardrails and classifiers are one layer, never the only one.
6. **Deterministic control over probabilistic.** Critical decisions are made by code and policy, not by the LLM alone.

## 2. Architectural measures

### 2.1 Permissions and isolation
- Separate credentials per agent, short-lived tokens, no shared admin keys.
- Sandbox for code and shell execution: container or VM, no network by default, restricted filesystem, CPU/memory/time limits.
- Split agents by task: an agent that reads untrusted data has **no** dangerous tools (the quarantined / privileged agent pattern).
- Isolate user and tenant data at the storage level, not only in the prompt.

### 2.2 Untrusted content
- Tag the source and trust level of every piece of context.
- Treat the output of an agent that processed external data as untrusted when it is passed on (to another agent, a tool, or a human).
- Do not let data drive tool selection: validate tool calls that originate "from data" against policy.
- Limit input size and format; strip hidden content (HTML comments, invisible Unicode, metadata) when it is not needed.

### 2.3 Actions and confirmations (human-in-the-loop)
- Classify actions: read / reversible write / **irreversible or external** (send, delete, pay, publish, deploy).
- Require human confirmation for irreversible actions, showing the **exact arguments**, not a model-written summary.
- Limits: number of actions per session, amounts, rate; cap agent loop depth.
- Provide dry-run and change previews wherever possible.

### 2.4 Egress control
- Allowlist domains for network tools and the browser; deny by default.
- Do not auto-render Markdown images or links to external domains from model output; sanitize URLs.
- Block access to internal addresses (SSRF): cloud metadata endpoints, localhost, RFC1918.
- Outgoing email and publishing go through explicit confirmation and a recipient filter.

### 2.5 Secrets and data
- Keep secrets out of the system prompt and context: assume anything in the context can leak.
- Inject secrets into tools server-side so the model never sees them.
- DLP and masking in output and logs: keys, tokens, PII.
- Minimize context: pass only the data that is required.

### 2.6 Memory
- Writing to long-term memory is a controlled action, with validation and a recorded source.
- Memory is separated per user and supports review, audit, and rollback.
- Untrusted sources do not write to memory without checks.

## 3. MCP and plugin security

- Use only vetted servers; **pin versions** and hashes, and watch for updates.
- Read tool `description` fields and schemas like code: look for hidden instructions and suspicious parameters.
- Require re-approval when a tool's description or capabilities change (rug pull protection).
- Keep the number of servers in one context small; isolate servers from each other to prevent tool shadowing.
- Validate arguments server-side: paths, commands, URLs (never trust input coming from the model).
- Run local MCP servers with limited privileges and in a sandbox; use minimally scoped tokens.
- Audit third-party servers before connecting them (source code, dependencies, where traffic goes).

## 4. Guardrails and filters

Useful as an extra layer, but they **do not replace** architectural measures.
- Input/output classifiers (Llama Guard, Prompt Guard, LLM Guard, NeMo Guardrails, and similar).
- Measure, do not assume: false positives on normal requests, miss rate on known attacks, latency.
- Structured output and strict tool-call schemas reduce the attack surface.
- Re-test regularly against new bypass techniques: filters go stale.

## 5. Monitoring and response

- Log prompts, context sources, tool calls with arguments, confirmations, and errors (respecting privacy).
- Alert on anomalies: unexpected tool calls, requests to new domains, data volume spikes, repeated policy denials.
- Kill switch: the ability to quickly disable an agent or individual tools.
- Response plan: token rotation, memory cleanup, transcript analysis.
- Run regular red team exercises (see the ai-agent-redteam skill) and regression tests for known injections.

## 6. Review checklist

```
Permissions and access
[ ] Each tool has minimal permissions and scope
[ ] Tokens are short-lived and separate
[ ] Dangerous tools are unavailable to agents that read untrusted data

Trifecta
[ ] Private data + untrusted content + external communication do not combine
    (or a compensating control is explicitly documented)

Actions
[ ] Irreversible actions require confirmation with exact arguments
[ ] There are limits on action count and rate

Data and network
[ ] Egress is allowlisted, SSRF is blocked
[ ] External images/links from output are not auto-rendered
[ ] No secrets in context, masking in logs

MCP / plugins
[ ] Versions pinned, descriptions reviewed, changes require re-approval
[ ] Servers isolated, arguments validated server-side

Memory
[ ] Writes are controlled, separated per user, auditable

Observability
[ ] Full tool-call logs, alerts, kill switch
[ ] Regular red team exercises and regression tests
```

## 7. How to give recommendations

- Start with **architectural** recommendations (permissions, isolation, egress), then prompt-level ones.
- Tie every recommendation to a specific risk and show what exactly it constrains.
- Prioritize by severity and ease of implementation: first what closes critical paths with minimal effort.
