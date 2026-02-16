# Flare

This is Flare — a local MCP server that provides real-time risk assessment for shell commands executed by AI coding agents.

## Project structure

- `src/index.ts` — MCP server entry point, registers the `assess_command` tool
- `src/parser.ts` — Shell command tokenizer (handles pipes, chains, quotes, redirects)
- `src/scorer.ts` — Aggregates analyzer findings into a risk level with summary and recommendation
- `src/types.ts` — Shared TypeScript interfaces (ParsedCommand, Finding, Analyzer, RiskAssessment)
- `src/analyzers/` — Five analyzers that run in parallel:
  - `destructive.ts` — rm -rf, DROP TABLE, git push --force
  - `permissions.ts` — sudo, chmod, chown
  - `sensitive-path.ts` — SSH keys, .env, cloud credentials, system files
  - `network.ts` — curl, wget, nc, data exfiltration patterns
  - `package-vuln.ts` — OSV.dev API lookups for npm/pip/cargo CVEs
- `tests/` — Vitest unit tests for parser, analyzers, and scorer

## Commands

- `npm run build` — Compile TypeScript to `dist/`
- `npm test` — Run all tests with Vitest
- `npm run dev` — Run directly with tsx (no build needed)

## Conventions

- TypeScript strict mode, ES2022 target, Node16 module resolution
- All analyzers implement the `Analyzer` interface from `src/types.ts`
- No external dependencies beyond `@modelcontextprotocol/sdk` and `zod` (transitive)
- Native `fetch` for HTTP (Node 18+), no `node-fetch`
- Deterministic analysis only — no LLM calls in the analysis path
- OSV.dev queries use AbortController with 1500ms timeout and in-memory caching

## Adding a new analyzer

1. Create `src/analyzers/your-analyzer.ts` implementing the `Analyzer` interface
2. Import and add it to the `analyzers` array in `src/index.ts`
3. Add tests in `tests/analyzers.test.ts`
