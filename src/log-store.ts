import { readFileSync } from "fs";
import type { RiskAssessment, RiskLevel, Action } from "./types.js";

export interface LogEntry {
  id: string;
  timestamp: string;
  command: string;
  cwd: string;
  duration_ms: number;
  assessment: RiskAssessment;
}

export interface LogQuery {
  search?: string;
  risk?: RiskLevel;
  action?: Action;
  partial?: boolean;
  from?: string;       // ISO timestamp
  to?: string;         // ISO timestamp
  sort?: string;       // field name
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
  after?: string;      // cursor: ISO timestamp for incremental polling
}

export interface LogQueryResult {
  entries: LogEntry[];
  total: number;       // total matching (before pagination)
  cursor: string;      // latest timestamp for next poll
}

export interface LogStore {
  query(q: LogQuery): LogQueryResult;
}

// --- JSONL file implementation ---

const RISK_ORDER: Record<string, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
const ACTION_ORDER: Record<string, number> = { run: 0, warn: 1, ask: 2 };

function parseJsonlFile(path: string): LogEntry[] {
  try {
    const raw = readFileSync(path, "utf-8");
    if (!raw.trim()) return [];
    const lines = raw.trim().split("\n");
    const entries: LogEntry[] = [];
    for (let i = 0; i < lines.length; i++) {
      try {
        const parsed = JSON.parse(lines[i]);
        entries.push({ id: String(i), ...parsed });
      } catch {}
    }
    return entries;
  } catch {
    return [];
  }
}

function matchesSearch(entry: LogEntry, search: string): boolean {
  const hay = [
    entry.command,
    entry.cwd,
    entry.assessment.risk_level,
    entry.assessment.action,
    entry.assessment.summary,
    ...entry.assessment.details.map(d => d.category + " " + d.description),
  ].join(" ").toLowerCase();
  return hay.includes(search);
}

function compareEntries(a: LogEntry, b: LogEntry, sort: string): number {
  switch (sort) {
    case "time": return a.timestamp.localeCompare(b.timestamp);
    case "risk": return (RISK_ORDER[a.assessment.risk_level] ?? 0) - (RISK_ORDER[b.assessment.risk_level] ?? 0);
    case "action": return (ACTION_ORDER[a.assessment.action] ?? 0) - (ACTION_ORDER[b.assessment.action] ?? 0);
    case "cmd": return a.command.localeCompare(b.command);
    case "ms": return a.duration_ms - b.duration_ms;
    default: return a.timestamp.localeCompare(b.timestamp);
  }
}

export function createJsonlStore(filePath: string): LogStore {
  return {
    query(q: LogQuery): LogQueryResult {
      let entries = parseJsonlFile(filePath);

      // Cursor-based: only return entries newer than `after`
      if (q.after) {
        entries = entries.filter(e => e.timestamp > q.after!);
      }

      // Filters
      if (q.risk) entries = entries.filter(e => e.assessment.risk_level === q.risk);
      if (q.action) entries = entries.filter(e => e.assessment.action === q.action);
      if (q.partial === true) entries = entries.filter(e => e.assessment.partial === true);
      if (q.partial === false) entries = entries.filter(e => !e.assessment.partial);
      if (q.from) entries = entries.filter(e => e.timestamp >= q.from!);
      if (q.to) entries = entries.filter(e => e.timestamp <= q.to!);
      if (q.search) {
        const s = q.search.toLowerCase();
        entries = entries.filter(e => matchesSearch(e, s));
      }

      const total = entries.length;

      // Sort
      const sort = q.sort ?? "time";
      const mul = (q.order ?? "desc") === "asc" ? 1 : -1;
      entries.sort((a, b) => compareEntries(a, b, sort) * mul);

      // Cursor: latest timestamp across all matched entries (before pagination)
      const cursor = entries.length > 0
        ? entries.reduce((max, e) => e.timestamp > max ? e.timestamp : max, entries[0].timestamp)
        : q.after ?? "";

      // Pagination
      const offset = q.offset ?? 0;
      const limit = q.limit ?? 200;
      entries = entries.slice(offset, offset + limit);

      return { entries, total, cursor };
    },
  };
}
