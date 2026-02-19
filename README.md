# Flare

Runtime risk assessment for AI coding agents. Flare intercepts shell commands before execution and provides contextual security analysis — so you see exactly what a command does and why it might be dangerous, right in the conversation.

This is not an enforcement tool. It does not block commands. It makes informed consent possible by surfacing risks that developers would otherwise miss.

## Quickstart

### 1. Install dependencies

```bash
npm install
npm run build
```

### 2. Add to Claude Code

Add Flare as an MCP server in your `.claude/settings.json`:

```json
{
  "mcpServers": {
    "flare": {
      "command": "node",
      "args": ["/absolute/path/to/flare/dist/index.js"]
    }
  }
}
```

### 3. Add the hook to your project's CLAUDE.md

```
Before executing any shell command, call flare.assess_command with the command and current working directory.
```

That's it. Flare will now analyze every command before you approve it.

## How it works

When an AI agent wants to run a shell command, Flare intercepts it and runs five analyzers in parallel:

```mermaid
graph LR
    CMD["Shell command"] --> P["Parser"]
    P --> A1["Package Vulnerability\nCVEs via OSV.dev"]
    P --> A2["Sensitive Path\nSSH keys, .env, creds"]
    P --> A3["Permissions\nsudo, chmod, chown"]
    P --> A4["Network\ncurl, wget, exfiltration"]
    P --> A5["Destructive\nrm -rf, DROP, force push"]
    A1 & A2 & A3 & A4 & A5 --> S["Scorer"]
    S --> R["Risk Assessment"]
```

Each command gets a risk level: `none`, `low`, `medium`, `high`, or `critical`.

When an API call (e.g. OSV.dev) fails or times out, the assessment is marked `partial: true` so you know the score may be incomplete.

## Example

You ask Claude to install an older version of express:

```
Claude: I need to install an older version of express for compatibility.
[calls assess_command("npm install express@4.16.0", "/home/dev/app")]

⚠️ MEDIUM RISK: express@4.16.0 has 2 known vulnerabilities:
• CVE-2024-29041 (medium): Open redirect via malicious URL
Recommendation: Consider using a newer version with known vulnerabilities patched.

Shall I proceed with 4.16.0 or upgrade to the latest?
```

## Risk levels

```mermaid
graph LR
    none["none\nNo issues found"] --- low["low\nNoted for awareness"]
    low --- medium["medium\nReview before approving"]
    medium --- high["high\nConsider alternatives"]
    high --- critical["critical\nStrongly discouraged"]

    style none fill:#d4edda,stroke:#155724,color:#155724
    style low fill:#d1ecf1,stroke:#0c5460,color:#0c5460
    style medium fill:#fff3cd,stroke:#856404,color:#856404
    style high fill:#f8d7da,stroke:#721c24,color:#721c24
    style critical fill:#721c24,stroke:#491217,color:#fff
```

## Logging

Every `assess_command` call is logged to a JSONL file at `~/.flare/logs/assess.jsonl`. Each line contains the command, working directory, full assessment, and timing. Logging is fire-and-forget — it never delays the response.

Configure the log path in `config.json`:

```json
{
  "logFile": "~/.flare/logs/assess.jsonl"
}
```

Set `"logFile": false` to disable logging.

## Dashboard

View logged assessments in a local web dashboard:

```bash
npm run dashboard
```

Opens at `http://localhost:6040`. Supports filtering by risk level, action, search text, and time range. Polls for new entries automatically.

## Configuration

Flare works with zero configuration. To customize, edit `config.json`:

```json
{
  "actionPolicy": {
    "none": "run",
    "low": "run",
    "medium": "warn",
    "high": "ask",
    "critical": "ask"
  },
  "sensitivePatterns": ["~/.myapp/secrets/*"],
  "packageAllowlist": ["lodash@4.17.21"],
  "osvTimeout": 1500,
  "safeHosts": ["internal.corp.com"],
  "commandAllowlist": ["echo *"],
  "logFile": "~/.flare/logs/assess.jsonl"
}
```

- **actionPolicy** — Maps risk levels to actions: `run` (silent), `warn` (show summary), `ask` (require confirmation)
- **sensitivePatterns** — Additional glob patterns to flag as sensitive
- **packageAllowlist** — Packages to suppress vulnerability warnings for
- **osvTimeout** — Milliseconds to wait for OSV.dev API (default: 1500)
- **safeHosts** — Hostnames to exclude from network exfiltration warnings
- **commandAllowlist** — Glob patterns for commands to skip analysis entirely
- **logFile** — Path to JSONL log file, or `false` to disable logging

## Development

```bash
npm install          # Install dependencies
npm run build        # Compile TypeScript
npm test             # Run tests
npm run dev          # Run with tsx (no build step)
npm run dashboard    # Launch log dashboard
```

## Architecture

```mermaid
graph TD
    subgraph src
        index.ts["index.ts — MCP server, tool registration, logging"]
        parser.ts["parser.ts — Shell command tokenizer"]
        scorer.ts["scorer.ts — Risk aggregation and summary"]
        types.ts["types.ts — Shared TypeScript interfaces"]
        logger.ts["logger.ts — Fire-and-forget JSONL logger"]
        log-store.ts["log-store.ts — Log query interface and JSONL impl"]
        dashboard.ts["dashboard.ts — Local web dashboard server"]

        subgraph analyzers
            destructive.ts["destructive.ts — rm -rf, DROP, git push -f"]
            permissions.ts["permissions.ts — sudo, chmod, chown"]
            sensitive-path.ts["sensitive-path.ts — SSH keys, .env, cloud creds"]
            network.ts["network.ts — curl, wget, nc, exfiltration"]
            package-vuln.ts["package-vuln.ts — OSV.dev CVE lookups"]
        end
    end

    index.ts --> parser.ts
    index.ts --> scorer.ts
    index.ts --> logger.ts
    index.ts --> analyzers
    dashboard.ts --> log-store.ts
```

## Requirements

- Node.js 18+
- Any MCP-compatible AI agent (Claude Code, Codex CLI)
