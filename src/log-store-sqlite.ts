import Database from "better-sqlite3";
import { mkdirSync } from "fs";
import { dirname } from "path";
import type { LogStore, LogEntry, LogQuery, LogQueryResult } from "./log-store.js";
import type { ParsedCommand, RiskAssessment } from "./types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS log_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  command TEXT NOT NULL,
  cwd TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  risk_level TEXT NOT NULL,
  action TEXT NOT NULL,
  partial INTEGER NOT NULL DEFAULT 0,
  assessment_json TEXT NOT NULL,
  parsed_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_timestamp ON log_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_risk_level ON log_entries(risk_level);
CREATE INDEX IF NOT EXISTS idx_action ON log_entries(action);
`;

interface SqliteRow {
  id: number;
  timestamp: string;
  command: string;
  cwd: string;
  duration_ms: number;
  risk_level: string;
  action: string;
  partial: number;
  assessment_json: string;
  parsed_json: string | null;
}

export interface SqliteLogWriter {
  write(
    command: string,
    cwd: string,
    assessment: RiskAssessment,
    durationMs: number,
    parsed?: ParsedCommand[],
  ): void;
}

export interface SqliteStore extends LogStore, SqliteLogWriter {
  close(): void;
}

export function createSqliteStore(dbPath: string): SqliteStore {
  mkdirSync(dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.exec(SCHEMA);

  const insertStmt = db.prepare(`
    INSERT INTO log_entries (timestamp, command, cwd, duration_ms, risk_level, action, partial, assessment_json, parsed_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  return {
    write(
      command: string,
      cwd: string,
      assessment: RiskAssessment,
      durationMs: number,
      parsed?: ParsedCommand[],
    ): void {
      const parsedJson = parsed && parsed.length > 0
        ? JSON.stringify(parsed.map(p => ({ verb: p.verb, args: p.args, operator: p.operator })))
        : null;

      insertStmt.run(
        new Date().toISOString(),
        command,
        cwd,
        durationMs,
        assessment.risk_level,
        assessment.action,
        assessment.partial ? 1 : 0,
        JSON.stringify(assessment),
        parsedJson,
      );
    },

    query(q: LogQuery): LogQueryResult {
      const conditions: string[] = [];
      const params: unknown[] = [];

      if (q.after) {
        // Support both id-based cursor (numeric) and timestamp-based cursor
        const afterNum = parseInt(q.after, 10);
        if (!isNaN(afterNum) && String(afterNum) === q.after) {
          conditions.push("id > ?");
          params.push(afterNum);
        } else {
          conditions.push("timestamp > ?");
          params.push(q.after);
        }
      }
      if (q.risk) {
        conditions.push("risk_level = ?");
        params.push(q.risk);
      }
      if (q.action) {
        conditions.push("action = ?");
        params.push(q.action);
      }
      if (q.partial === true) {
        conditions.push("partial = 1");
      } else if (q.partial === false) {
        conditions.push("partial = 0");
      }
      if (q.from) {
        conditions.push("timestamp >= ?");
        params.push(q.from);
      }
      if (q.to) {
        conditions.push("timestamp <= ?");
        params.push(q.to);
      }
      if (q.search) {
        conditions.push("(command LIKE ? OR cwd LIKE ? OR assessment_json LIKE ?)");
        const pattern = `%${q.search}%`;
        params.push(pattern, pattern, pattern);
      }

      const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

      // Count total
      const countSql = `SELECT COUNT(*) as cnt FROM log_entries ${where}`;
      const totalRow = db.prepare(countSql).get(...params) as { cnt: number };
      const total = totalRow.cnt;

      // Sort
      const sortMap: Record<string, string> = {
        time: "timestamp",
        risk: "risk_level",
        action: "action",
        cmd: "command",
        ms: "duration_ms",
      };
      const sortCol = sortMap[q.sort ?? "time"] ?? "timestamp";
      const orderDir = (q.order ?? "desc").toUpperCase();
      const orderClause = `ORDER BY ${sortCol} ${orderDir}`;

      // Pagination
      const limit = q.limit ?? 200;
      const offset = q.offset ?? 0;

      const selectSql = `SELECT * FROM log_entries ${where} ${orderClause} LIMIT ? OFFSET ?`;
      const rows = db.prepare(selectSql).all(...params, limit, offset) as SqliteRow[];

      // Find cursor (max id across all matching, not just this page)
      // Use id-based cursor for reliable incremental polling (timestamps can collide)
      let cursor = q.after ?? "0";
      if (total > 0) {
        const cursorRow = db.prepare(
          `SELECT MAX(id) as mx FROM log_entries ${where}`
        ).get(...params) as { mx: number | null };
        cursor = String(cursorRow.mx ?? cursor);
      }

      const entries: LogEntry[] = rows.map(row => ({
        id: String(row.id),
        timestamp: row.timestamp,
        command: row.command,
        cwd: row.cwd,
        duration_ms: row.duration_ms,
        assessment: JSON.parse(row.assessment_json) as RiskAssessment,
      }));

      return { entries, total, cursor };
    },

    close(): void {
      db.close();
    },
  };
}
