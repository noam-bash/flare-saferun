import { appendFile, mkdir } from "fs/promises";
import { dirname } from "path";
import type { ParsedCommand, RiskAssessment } from "./types.js";

interface LogEntryJson {
  timestamp: string;
  command: string;
  cwd: string;
  duration_ms: number;
  assessment: RiskAssessment;
  parsed_commands?: Array<{ verb: string; args: string[]; operator: string | null }>;
}

/**
 * Abstraction for log writing backends.
 */
export interface LogWriter {
  write(
    command: string,
    cwd: string,
    assessment: RiskAssessment,
    durationMs: number,
    parsed?: ParsedCommand[],
  ): void;
}

let activeWriter: LogWriter | null = null;

// JSONL writer state
let logFilePath: string | false = false;
let dirEnsured = false;
let writeChain: Promise<void> = Promise.resolve();

/**
 * Initialize the logger with the configured log file path (JSONL backend).
 * Pass `false` to disable logging entirely.
 */
export function initLogger(path: string | false): void {
  logFilePath = path;
  dirEnsured = false;
  writeChain = Promise.resolve();
  activeWriter = null; // Use built-in JSONL writer
}

/**
 * Initialize the logger with a custom LogWriter backend (e.g. SQLite).
 */
export function initLoggerWithWriter(writer: LogWriter): void {
  activeWriter = writer;
  logFilePath = false; // Disable JSONL
}

/**
 * Write a log entry. Fire-and-forget — errors are silently swallowed.
 * Writes are serialized to preserve ordering.
 * MUST NOT be awaited in the request path.
 */
export function writeLogEntry(
  command: string,
  cwd: string,
  assessment: RiskAssessment,
  durationMs: number,
  parsed?: ParsedCommand[],
): void {
  // Custom writer (e.g. SQLite)
  if (activeWriter) {
    try {
      activeWriter.write(command, cwd, assessment, durationMs, parsed);
    } catch {
      // Silently swallow
    }
    return;
  }

  // JSONL writer
  if (logFilePath === false) return;

  const entry: LogEntryJson = {
    timestamp: new Date().toISOString(),
    command,
    cwd,
    duration_ms: durationMs,
    assessment,
  };

  if (parsed && parsed.length > 0) {
    entry.parsed_commands = parsed.map(p => ({
      verb: p.verb,
      args: p.args,
      operator: p.operator,
    }));
  }

  const line = JSON.stringify(entry) + "\n";
  const path = logFilePath;
  writeChain = writeChain.then(() => doWrite(path, line)).catch(() => {});
}

async function doWrite(filePath: string, line: string): Promise<void> {
  if (!dirEnsured) {
    await mkdir(dirname(filePath), { recursive: true });
    dirEnsured = true;
  }
  await appendFile(filePath, line, "utf-8");
}
