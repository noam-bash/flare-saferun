import { appendFile, mkdir } from "fs/promises";
import { dirname } from "path";
import type { ParsedCommand, RiskAssessment } from "./types.js";

interface LogEntry {
  timestamp: string;
  command: string;
  cwd: string;
  duration_ms: number;
  assessment: RiskAssessment;
  parsed_commands?: Array<{ verb: string; args: string[]; operator: string | null }>;
}

let logFilePath: string | false = false;
let dirEnsured = false;
let writeChain: Promise<void> = Promise.resolve();

/**
 * Initialize the logger with the configured log file path.
 * Pass `false` to disable logging entirely.
 */
export function initLogger(path: string | false): void {
  logFilePath = path;
  dirEnsured = false;
  writeChain = Promise.resolve();
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
  if (logFilePath === false) return;

  const entry: LogEntry = {
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
