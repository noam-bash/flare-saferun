import { describe, it, expect, afterEach } from "vitest";
import { rm } from "fs/promises";
import { join } from "path";
import { tmpdir } from "os";
import { createSqliteStore, type SqliteStore } from "../src/log-store-sqlite.js";
import type { RiskAssessment } from "../src/types.js";

const TEST_DIR = join(tmpdir(), `flare-sqlite-test-${process.pid}`);
const openStores: SqliteStore[] = [];

function testDbPath(name: string): string {
  return join(TEST_DIR, name, "test.db");
}

function makeStore(name: string): SqliteStore {
  const store = createSqliteStore(testDbPath(name));
  openStores.push(store);
  return store;
}

const SAMPLE_ASSESSMENT: RiskAssessment = {
  risk_level: "none",
  action: "run",
  summary: "No security concerns detected.",
  details: [],
  recommendation: "Command appears safe to execute.",
};

const HIGH_ASSESSMENT: RiskAssessment = {
  risk_level: "high",
  action: "ask",
  summary: "High risk",
  details: [
    { category: "destructive", severity: "high", description: "rm -rf /", analyzer: "destructive" },
  ],
  recommendation: "Review carefully.",
};

afterEach(async () => {
  // Close all open stores before cleanup
  for (const store of openStores) {
    try { store.close(); } catch {}
  }
  openStores.length = 0;
  await rm(TEST_DIR, { recursive: true, force: true });
});

describe("SQLite LogStore", () => {
  it("writes and reads entries", () => {
    const store = makeStore("basic");
    store.write("ls -la", "/tmp", SAMPLE_ASSESSMENT, 5);
    store.write("rm -rf /", "/", HIGH_ASSESSMENT, 10);

    const result = store.query({});
    expect(result.total).toBe(2);
    expect(result.entries).toHaveLength(2);
  });

  it("filters by risk level", () => {
    const store = makeStore("risk-filter");
    store.write("ls", "/tmp", SAMPLE_ASSESSMENT, 1);
    store.write("rm -rf /", "/", HIGH_ASSESSMENT, 2);

    const result = store.query({ risk: "high" });
    expect(result.total).toBe(1);
    expect(result.entries[0].command).toBe("rm -rf /");
  });

  it("filters by action", () => {
    const store = makeStore("action-filter");
    store.write("ls", "/tmp", SAMPLE_ASSESSMENT, 1);
    store.write("rm -rf /", "/", HIGH_ASSESSMENT, 2);

    const result = store.query({ action: "ask" });
    expect(result.total).toBe(1);
    expect(result.entries[0].assessment.action).toBe("ask");
  });

  it("supports text search", () => {
    const store = makeStore("search");
    store.write("ls -la", "/tmp", SAMPLE_ASSESSMENT, 1);
    store.write("rm -rf /data", "/home", HIGH_ASSESSMENT, 2);

    const result = store.query({ search: "rm" });
    expect(result.total).toBe(1);
    expect(result.entries[0].command).toContain("rm");
  });

  it("supports pagination", () => {
    const store = makeStore("paging");
    for (let i = 0; i < 5; i++) {
      store.write(`cmd-${i}`, "/tmp", SAMPLE_ASSESSMENT, i);
    }

    const page1 = store.query({ limit: 2, offset: 0 });
    expect(page1.total).toBe(5);
    expect(page1.entries).toHaveLength(2);

    const page2 = store.query({ limit: 2, offset: 2 });
    expect(page2.entries).toHaveLength(2);

    const page3 = store.query({ limit: 2, offset: 4 });
    expect(page3.entries).toHaveLength(1);
  });

  it("supports cursor-based polling", () => {
    const store = makeStore("cursor");
    store.write("cmd-1", "/tmp", SAMPLE_ASSESSMENT, 1);

    const initial = store.query({});
    expect(initial.total).toBe(1);
    const cursor = initial.cursor;

    // Write more entries
    store.write("cmd-2", "/tmp", SAMPLE_ASSESSMENT, 2);

    const incremental = store.query({ after: cursor });
    expect(incremental.total).toBe(1);
    expect(incremental.entries[0].command).toBe("cmd-2");
  });

  it("sorts by different columns", () => {
    const store = makeStore("sorting");
    store.write("alpha", "/tmp", SAMPLE_ASSESSMENT, 100);
    store.write("zeta", "/tmp", HIGH_ASSESSMENT, 1);

    const byCmd = store.query({ sort: "cmd", order: "asc" });
    expect(byCmd.entries[0].command).toBe("alpha");
    expect(byCmd.entries[1].command).toBe("zeta");

    const byMs = store.query({ sort: "ms", order: "desc" });
    expect(byMs.entries[0].duration_ms).toBe(100);
  });

  it("stores parsed commands", () => {
    const store = makeStore("parsed");
    store.write("cat /etc/passwd | grep root", "/tmp", SAMPLE_ASSESSMENT, 1, [
      { verb: "cat", args: ["/etc/passwd"], operator: "|", redirects: [], rawSegment: "cat /etc/passwd", position: 0 },
      { verb: "grep", args: ["root"], operator: null, redirects: [], rawSegment: "grep root", position: 1 },
    ]);

    const result = store.query({});
    expect(result.total).toBe(1);
  });

  it("preserves assessment details including analyzer", () => {
    const store = makeStore("details");
    store.write("rm -rf /", "/", HIGH_ASSESSMENT, 10);

    const result = store.query({});
    expect(result.entries[0].assessment.details[0].analyzer).toBe("destructive");
    expect(result.entries[0].assessment.details[0].severity).toBe("high");
  });

  it("filters partial assessments", () => {
    const store = makeStore("partial");
    const partialAssessment: RiskAssessment = {
      ...SAMPLE_ASSESSMENT,
      risk_level: "medium",
      action: "warn",
      partial: true,
    };
    store.write("npm install pkg@1.0.0", "/tmp", partialAssessment, 5);
    store.write("ls", "/tmp", SAMPLE_ASSESSMENT, 1);

    const partialOnly = store.query({ partial: true });
    expect(partialOnly.total).toBe(1);
    expect(partialOnly.entries[0].assessment.partial).toBe(true);

    const completeOnly = store.query({ partial: false });
    expect(completeOnly.total).toBe(1);
    expect(completeOnly.entries[0].assessment.partial).toBeUndefined();
  });
});
