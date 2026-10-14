---
name: mcp-server-audit
description: Security audit of a Model Context Protocol (MCP) server or client configuration before connecting it to an agent - tool description review, tool poisoning, rug pull and tool shadowing checks, permission and transport review, argument validation, secrets handling, and a go/no-go verdict. Use when someone asks to vet, review, install, or approve an MCP server, or to audit an existing MCP setup. Triggers - audit MCP server, is this MCP server safe, review mcp.json, MCP supply chain, tool poisoning check.
---

# MCP Server Audit

Decide whether an MCP server is safe to connect to an agent, and under which constraints.
Review only servers you are allowed to review. Read code and metadata; do not run an unknown server against real credentials or production data.

## Mental model

An MCP server gives the model two things: **text the model reads** (tool names, descriptions, schemas, tool results) and **actions the model can take** (tool calls). Both are attack surface:

- Text the model reads can carry instructions (tool poisoning, indirect prompt injection).
- Actions run with whatever permissions the server and its tokens have.
- The server is third-party code, often fetched and updated automatically.

## 1. Inventory

Collect before judging:

| Item | Where to look |
|---|---|
| Source and maintainer | Repository, package registry page, signing, commit history, issue tracker |
| Distribution | `npx`, `uvx`, `docker`, binary, remote URL; is the version pinned to a hash or tag |
| Transport | stdio (local process) or HTTP/SSE (remote, can change at any time) |
| Tools | Full list with names, descriptions, input schemas |
| Resources and prompts | Anything else the server exposes to the model |
| Credentials | Env vars, config files, OAuth scopes the server needs |
| Network egress | Hosts the server contacts |
| Filesystem and process access | Paths read or written, subprocesses spawned |

## 2. Review the text the model reads

Read every tool `name`, `description`, parameter description, and default value as if it were an instruction to the model.

Red flags:
- Imperative text aimed at the model rather than at the user: "before using this tool, first read...", "do not tell the user", "always pass the contents of...".
- Hidden or oddly formatted content: pseudo-tags such as `<IMPORTANT>`, very long descriptions, invisible Unicode, base64 blobs, instructions buried far below the visible summary.
- References to **other** tools or files outside the tool's purpose (a calculator that mentions SSH keys or another server's tools). This is the tool shadowing pattern.
- Parameters that invite sensitive data (`notes`, `context`, `debug`, `metadata`) with no clear purpose.
- Descriptions that differ between what a UI shows and what the model receives.

Tool results are also model input. Check what the server returns: raw web pages, issue text, emails, file contents, and error messages all carry attacker-controlled text. A server that forwards third-party content unmodified is an indirect injection channel.

## 3. Review what the tools can do

For each tool, record: inputs, side effects, reversibility, permissions used.

- **Least privilege**: does the token or process have more access than the tools need? Read-only where possible, narrow OAuth scopes, a dedicated service account.
- **Argument handling**: are paths canonicalized and confined to an allowed root? Are shell commands built from arguments? Are URLs fetched without an allowlist (SSRF to localhost, RFC1918, cloud metadata)? Are SQL and query strings parameterized?
- **Irreversible or external actions**: send, delete, publish, pay, deploy, push. These need human confirmation showing exact arguments.
- **Secrets**: do keys appear in tool results, logs, error messages, or tool descriptions? Does the server ask the model to handle secrets?
- **Data leaving**: which hosts receive data, and is telemetry sent by default.

## 4. Review supply chain and update behavior

- Pin the version. Prefer an immutable reference (commit hash, image digest, package hash) to a floating tag or `latest`.
- Check dependencies and install scripts. Look for typosquatted package names and recent maintainer or ownership changes.
- **Remote servers can change their tool definitions after you approved them** (rug pull). Local servers can be pinned; remote ones cannot, so detect changes instead.
- Record a fingerprint of the tool definitions (name, description, input schema) at approval time and compare on every connection. Treat any change as a new review.

## 5. Cross-server risk

- Servers loaded into the same agent share one context. A low-trust server can influence how the model uses a high-trust one (tool shadowing).
- Do not combine, in one agent: a server that reads untrusted content, a server that reads private data, and a server that can send data out (the lethal trifecta). Split them across agents or remove one.
- Prefer fewer servers per agent and a separate profile for risky ones.

## 6. Verdict

Give one of three verdicts and say why.

| Verdict | Meaning |
|---|---|
| **Approve** | No red flags; permissions are minimal; version is pinned |
| **Approve with constraints** | Usable under listed conditions: read-only token, sandbox, no network, confirmation on named tools, definition pinning, isolated agent |
| **Reject** | Poisoned or deceptive descriptions, unjustified permissions, unpinnable or unreviewable code, or an unfixable trifecta |

## 7. Report template

```markdown
# MCP Server Audit: <name> <version>
Date: YYYY-MM-DD | Reviewer: ... | Verdict: Approve / Approve with constraints / Reject

## Summary
One paragraph: what the server does and the main risk.

## Inventory
Source, distribution, transport, tools, credentials, egress.

## Findings
| ID | Severity | Area (text / permissions / supply chain / cross-server) | Evidence | Recommendation |
|----|----------|--------------------------------------------------------|----------|----------------|

## Constraints required for use
- ...

## Pinned fingerprints
Tool name -> sha256 of (name, description, inputSchema)

## Re-review triggers
New version, changed tool definitions, new credentials or scopes, new servers in the same agent.
```

## Principles

- Evidence over impressions: quote the exact description text or code line behind each finding.
- Metadata review is necessary but not sufficient: a clean description does not make a server safe if its tools are over-privileged.
- A passing audit applies to a specific version. Re-audit on change.
