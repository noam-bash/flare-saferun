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
      "args": ["dist/index.js"],
      "cwd": "/path/to/flare"
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

| Analyzer | What it catches |
|----------|----------------|
| **Package Vulnerability** | Known CVEs in npm, pip, and cargo packages via [OSV.dev](https://osv.dev) |
| **Sensitive Path** | Reads/writes to SSH keys, cloud credentials, `.env` files, system auth files |
| **Permissions** | `sudo`, `chmod 777`, `chown` on system paths |
| **Network** | Data exfiltration via `curl`, `wget`, `nc`, piped sensitive data |
| **Destructive** | `rm -rf /`, `DROP TABLE`, `git push --force`, filesystem formatting |

Each command gets a risk level: `none`, `low`, `medium`, `high`, or `critical`.

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

| Level | Meaning |
|-------|---------|
| `none` | No issues found — proceed normally |
| `low` | Informational — noted for awareness |
| `medium` | Warning — review details before approving |
| `high` | Significant risk — review full report, consider alternatives |
| `critical` | Dangerous — strongly recommended against |

## Configuration

Flare works with zero configuration. To customize, edit `config.json`:

```json
{
  "sensitivePatterns": ["~/.myapp/secrets/*"],
  "packageAllowlist": ["lodash@4.17.21"],
  "osvTimeout": 1500
}
```

- **sensitivePatterns** — Additional glob patterns to flag as sensitive
- **packageAllowlist** — Packages to suppress vulnerability warnings for
- **osvTimeout** — Milliseconds to wait for OSV.dev API (default: 1500)

## Development

```bash
npm install          # Install dependencies
npm run build        # Compile TypeScript
npm test             # Run tests
npm run dev          # Run with tsx (no build step)
```

## Architecture

```
src/
├── index.ts              # MCP server, tool registration
├── parser.ts             # Shell command tokenizer
├── scorer.ts             # Risk aggregation and summary generation
├── types.ts              # Shared TypeScript interfaces
└── analyzers/
    ├── destructive.ts    # rm -rf, DROP, git push -f
    ├── permissions.ts    # sudo, chmod, chown
    ├── sensitive-path.ts # SSH keys, .env, cloud creds
    ├── network.ts        # curl, wget, nc, exfiltration
    └── package-vuln.ts   # OSV.dev CVE lookups
```

## Requirements

- Node.js 18+
- Any MCP-compatible AI agent (Claude Code, Codex CLI)
