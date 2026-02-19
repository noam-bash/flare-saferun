import { describe, it, expect, afterEach } from "vitest";
import { initLogger, writeLogEntry } from "../src/logger.js";
import { readFile, rm, access } from "fs/promises";
import { join } from "path";
import { tmpdir } from "os";
import type { RiskAssessment } from "../src/types.js";

const TEST_DIR = join(tmpdir(), `flare-log-test-${process.pid}`);

function testLogFile(name: string): string {
  return join(TEST_DIR, name, "test.jsonl");
}

const SAMPLE_ASSESSMENT: RiskAssessment = {
  risk_level: "none",
  action: "run",
  summary: "No security concerns detected.",
  details: [],
  recommendation: "Command appears safe to execute.",
};

// Wait for fire-and-forget writes to settle
function settle(): Promise<void> {
  return new Promise(r => setTimeout(r, 150));
}

afterEach(async () => {
  await rm(TEST_DIR, { recursive: true, force: true });
});

describe("logger", () => {
  it("writes a valid JSONL entry", async () => {
    const logFile = testLogFile("basic");
    initLogger(logFile);
    writeLogEntry("ls -la", "/tmp", SAMPLE_ASSESSMENT, 5);
    await settle();

    const content = await readFile(logFile, "utf-8");
    const entry = JSON.parse(content.trim());
    expect(entry.command).toBe("ls -la");
    expect(entry.cwd).toBe("/tmp");
    expect(entry.duration_ms).toBe(5);
    expect(entry.assessment.risk_level).toBe("none");
    expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("appends multiple entries as separate lines", async () => {
    const logFile = testLogFile("multi");
    initLogger(logFile);
    writeLogEntry("cmd1", "/a", SAMPLE_ASSESSMENT, 1);
    writeLogEntry("cmd2", "/b", SAMPLE_ASSESSMENT, 2);
    writeLogEntry("cmd3", "/c", SAMPLE_ASSESSMENT, 3);
    await settle();

    const content = await readFile(logFile, "utf-8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(3);
    expect(JSON.parse(lines[0]).command).toBe("cmd1");
    expect(JSON.parse(lines[1]).command).toBe("cmd2");
    expect(JSON.parse(lines[2]).command).toBe("cmd3");
  });

  it("does not write when disabled", async () => {
    const logFile = testLogFile("disabled");
    initLogger(false);
    writeLogEntry("rm -rf /", "/", SAMPLE_ASSESSMENT, 1);
    await settle();

    await expect(access(logFile)).rejects.toThrow();
  });

  it("creates the directory if it does not exist", async () => {
    const logFile = join(TEST_DIR, "deep", "nested", "dir", "test.jsonl");
    initLogger(logFile);
    writeLogEntry("echo hello", "/tmp", SAMPLE_ASSESSMENT, 0);
    await settle();

    const content = await readFile(logFile, "utf-8");
    expect(JSON.parse(content.trim()).command).toBe("echo hello");
  });

  it("silently swallows write errors", async () => {
    // Point to an invalid path (a file as a directory)
    const logFile = testLogFile("error");
    initLogger(logFile);
    // Write one entry to create the file
    writeLogEntry("first", "/tmp", SAMPLE_ASSESSMENT, 0);
    await settle();

    // Now point to a path where the "file" from above is used as a directory
    const badPath = join(logFile, "impossible", "path.jsonl");
    initLogger(badPath);
    // This should not throw
    writeLogEntry("second", "/tmp", SAMPLE_ASSESSMENT, 0);
    await settle();

    // Original file should still have only the first entry
    const content = await readFile(logFile, "utf-8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(1);
  });

  it("includes the full assessment in the log entry", async () => {
    const logFile = testLogFile("full-assessment");
    const assessment: RiskAssessment = {
      risk_level: "critical",
      action: "ask",
      summary: "Critical risk",
      details: [{ category: "destructive", severity: "critical", description: "rm -rf /" }],
      recommendation: "Do not proceed.",
      partial: true,
    };
    initLogger(logFile);
    writeLogEntry("rm -rf /", "/", assessment, 42);
    await settle();

    const content = await readFile(logFile, "utf-8");
    const entry = JSON.parse(content.trim());
    expect(entry.assessment).toEqual(assessment);
    expect(entry.duration_ms).toBe(42);
  });
});
