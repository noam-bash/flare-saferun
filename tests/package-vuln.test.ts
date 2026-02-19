import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { parseCommand } from "../src/parser.js";
import { scoreRisk } from "../src/scorer.js";
import { destructiveAnalyzer } from "../src/analyzers/destructive.js";
import { permissionsAnalyzer } from "../src/analyzers/permissions.js";
import { createSensitivePathAnalyzer } from "../src/analyzers/sensitive-path.js";
import { createNetworkAnalyzer } from "../src/analyzers/network.js";
import { createPackageVulnAnalyzer } from "../src/analyzers/package-vuln.js";
import type { Analyzer, ActionPolicy, RiskAssessment } from "../src/types.js";

// Full pipeline — mirrors index.ts assess_command logic
const DEFAULT_POLICY: ActionPolicy = {
  none: "run",
  low: "run",
  medium: "warn",
  high: "ask",
  critical: "ask",
};

function buildPipeline(osvTimeout = 1500): Analyzer[] {
  return [
    destructiveAnalyzer,
    permissionsAnalyzer,
    createSensitivePathAnalyzer([]),
    createNetworkAnalyzer([]),
    createPackageVulnAnalyzer(osvTimeout),
  ];
}

async function assessCommand(
  command: string,
  cwd = "/tmp",
  policy = DEFAULT_POLICY,
  osvTimeout = 1500,
): Promise<RiskAssessment> {
  const parsed = parseCommand(command);
  const analyzers = buildPipeline(osvTimeout);
  const results = await Promise.all(analyzers.map(a => a.analyze(parsed, cwd)));
  return scoreRisk(results, policy);
}

function mockOsv(response: object, status = 200) {
  return vi.spyOn(globalThis, "fetch").mockResolvedValue({
    ok: status >= 200 && status < 300,
    json: async () => response,
  } as Response);
}

function mockOsvDown() {
  return vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("Network error"));
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("integration: package install with known vulnerabilities", () => {
  it("critical CVE produces critical risk and ask action", async () => {
    mockOsv({
      vulns: [
        {
          id: "CVE-2024-1234",
          summary: "Remote code execution",
          severity: [{ type: "CVSS_V3", score: "9.8" }],
        },
      ],
    });
    const result = await assessCommand("npm install express@4.16.0");
    expect(result.risk_level).toBe("critical");
    expect(result.action).toBe("ask");
    expect(result.partial).toBeUndefined();
    expect(result.details).toHaveLength(1);
    expect(result.details[0].category).toBe("package-vulnerability");
    expect(result.details[0].description).toContain("CVE-2024-1234");
    expect(result.details[0].description).toContain("CVSS 9.8");
    expect(result.recommendation).toBeTruthy();
  });

  it("high CVE produces high risk and ask action", async () => {
    mockOsv({
      vulns: [
        {
          id: "CVE-2024-5678",
          severity: [{ type: "CVSS_V3", score: "7.5" }],
        },
      ],
    });
    const result = await assessCommand("pip install django==3.2.0");
    expect(result.risk_level).toBe("high");
    expect(result.action).toBe("ask");
    expect(result.details[0].severity).toBe("high");
  });

  it("medium CVE produces medium risk and warn action", async () => {
    mockOsv({
      vulns: [
        {
          id: "CVE-2024-9999",
          severity: [{ type: "CVSS_V3", score: "5.3" }],
        },
      ],
    });
    const result = await assessCommand("cargo add serde@1.0.100");
    expect(result.risk_level).toBe("medium");
    expect(result.action).toBe("warn");
  });

  it("low CVE produces low risk and run action", async () => {
    mockOsv({
      vulns: [
        {
          id: "CVE-2024-0001",
          severity: [{ type: "CVSS_V3", score: "2.1" }],
        },
      ],
    });
    const result = await assessCommand("npm install pkg@1.0.0");
    expect(result.risk_level).toBe("low");
    expect(result.action).toBe("run");
  });

  it("clean package produces no risk", async () => {
    mockOsv({ vulns: [] });
    const result = await assessCommand("npm install express@4.21.0");
    expect(result.risk_level).toBe("none");
    expect(result.action).toBe("run");
    expect(result.details).toHaveLength(0);
  });
});

describe("integration: OSV.dev unreachable — warns about unknown status", () => {
  it("network error produces medium warning about unknown vulnerability status", async () => {
    mockOsvDown();
    // Use unique package name to avoid cache from prior tests
    const result = await assessCommand("npm install netfail-pkg@1.0.0");
    expect(result.risk_level).toBe("medium");
    expect(result.action).toBe("warn");
    expect(result.partial).toBe(true);
    expect(result.details).toHaveLength(1);
    expect(result.details[0].description).toContain("vulnerability status unknown");
  });

  it("HTTP 500 produces medium warning about unknown vulnerability status", async () => {
    mockOsv({ error: "internal server error" }, 500);
    const result = await assessCommand("npm install http500-pkg@1.0.0");
    expect(result.risk_level).toBe("medium");
    expect(result.action).toBe("warn");
    expect(result.partial).toBe(true);
    expect(result.details[0].description).toContain("OSV API returned HTTP");
  });

  it("timeout produces medium warning about unknown vulnerability status", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(
      () => new Promise((_, reject) => setTimeout(() => reject(new Error("aborted")), 50))
    );
    const result = await assessCommand("npm install timeout-pkg@1.0.0", "/tmp", DEFAULT_POLICY, 10);
    expect(result.risk_level).toBe("medium");
    expect(result.action).toBe("warn");
    expect(result.partial).toBe(true);
    expect(result.details[0].description).toContain("vulnerability status unknown");
  });

  it("malformed API response results in no findings", async () => {
    mockOsv({ unexpected: "data" });
    const result = await assessCommand("npm install malformed-pkg@1.0.0");
    expect(result.risk_level).toBe("none");
    expect(result.action).toBe("run");
    expect(result.partial).toBeUndefined();
  });
});

describe("integration: package vuln combined with other risk signals", () => {
  it("vulnerable package installed via sudo escalates risk", async () => {
    mockOsv({
      vulns: [
        { id: "CVE-2024-0001", severity: [{ type: "CVSS_V3", score: "7.0" }] },
      ],
    });
    const result = await assessCommand("sudo npm install express@4.16.0");
    // sudo triggers permissions analyzer (high) + package-vuln (high) = amplified
    expect(result.details.length).toBeGreaterThanOrEqual(2);
    expect(result.details.some(d => d.category === "package-vulnerability")).toBe(true);
    expect(result.details.some(d => d.category === "permissions")).toBe(true);
    // 2 high findings → amplified to critical
    expect(result.risk_level).toBe("critical");
    expect(result.action).toBe("ask");
  });

  it("non-install commands are unaffected by OSV mock", async () => {
    const spy = mockOsv({ vulns: [{ id: "CVE-2024-9999", severity: [{ type: "CVSS_V3", score: "9.8" }] }] });
    const result = await assessCommand("npm run build");
    // Package-vuln analyzer doesn't fire for non-install commands
    expect(spy).not.toHaveBeenCalled();
    expect(result.risk_level).toBe("none");
  });

  it("versionless install skips OSV lookup", async () => {
    const spy = mockOsv({ vulns: [] });
    const result = await assessCommand("npm install express");
    expect(spy).not.toHaveBeenCalled();
    expect(result.risk_level).toBe("none");
  });
});

describe("integration: action policy customization", () => {
  it("custom policy can downgrade medium vuln to run", async () => {
    mockOsv({
      vulns: [{ id: "CVE-2024-0001", severity: [{ type: "CVSS_V3", score: "5.0" }] }],
    });
    const lenientPolicy: ActionPolicy = {
      none: "run",
      low: "run",
      medium: "run",
      high: "warn",
      critical: "ask",
    };
    // Use unique package name to avoid cache from prior tests
    const result = await assessCommand("npm install lenient-pkg@1.0.0", "/tmp", lenientPolicy);
    expect(result.risk_level).toBe("medium");
    expect(result.action).toBe("run"); // lenient policy overrides default "warn"
  });

  it("strict policy can upgrade low vuln to ask", async () => {
    mockOsv({
      vulns: [{ id: "CVE-2024-0001", severity: [{ type: "CVSS_V3", score: "2.0" }] }],
    });
    const strictPolicy: ActionPolicy = {
      none: "run",
      low: "ask",
      medium: "ask",
      high: "ask",
      critical: "ask",
    };
    // Use unique package name to avoid cache from prior tests
    const result = await assessCommand("npm install strict-pkg@1.0.0", "/tmp", strictPolicy);
    expect(result.risk_level).toBe("low");
    expect(result.action).toBe("ask"); // strict policy overrides default "run"
  });
});

// ---------------------------------------------------------------------------
// Live integration tests — hit the real OSV.dev API
// Skipped when SKIP_LIVE_TESTS=1 (e.g. offline CI environments)
// Uses a generous timeout since these make real network calls
// ---------------------------------------------------------------------------
const LIVE_TIMEOUT = 10_000;
const skip = process.env.SKIP_LIVE_TESTS === "1";
const describeL = skip ? describe.skip : describe;

function assessCommandLive(command: string, cwd = "/tmp"): Promise<RiskAssessment> {
  const parsed = parseCommand(command);
  // Use a generous timeout for real API calls
  const analyzers = buildPipeline(5000);
  const results = Promise.all(analyzers.map(a => a.analyze(parsed, cwd)));
  return results.then(r => scoreRisk(r, DEFAULT_POLICY));
}

describeL("live: real OSV.dev API", () => {
  it("lodash@4.17.4 has known vulnerabilities", async () => {
    const result = await assessCommandLive("npm install lodash@4.17.4");
    expect(result.partial).toBeUndefined();
    expect(result.risk_level).not.toBe("none");
    expect(result.action).toBe("ask");
    const vulnDetail = result.details.find(d => d.category === "package-vulnerability");
    expect(vulnDetail).toBeDefined();
    expect(vulnDetail!.description).toContain("lodash@4.17.4");
    expect(vulnDetail!.description).toMatch(/known vulnerabilit/);
  }, LIVE_TIMEOUT);

  it("express@4.21.0 (recent patched) has no known vulnerabilities", async () => {
    const result = await assessCommandLive("npm install express@4.21.0");
    expect(result.partial).toBeUndefined();
    const vulnDetail = result.details.find(d => d.category === "package-vulnerability");
    expect(vulnDetail).toBeUndefined();
  }, LIVE_TIMEOUT);

  it("sudo npm install lodash@4.17.4 flags both permissions and vulnerabilities", async () => {
    const result = await assessCommandLive("sudo npm install lodash@4.17.4");
    expect(result.partial).toBeUndefined();
    expect(result.details.some(d => d.category === "permissions")).toBe(true);
    expect(result.details.some(d => d.category === "package-vulnerability")).toBe(true);
    expect(result.risk_level).toBe("critical");
  }, LIVE_TIMEOUT);

  it("requests-2.19.1 (PyPI) has known vulnerabilities", async () => {
    const result = await assessCommandLive("pip install requests==2.19.1");
    expect(result.partial).toBeUndefined();
    const vulnDetail = result.details.find(d => d.category === "package-vulnerability");
    expect(vulnDetail).toBeDefined();
    expect(vulnDetail!.description).toContain("requests@2.19.1");
  }, LIVE_TIMEOUT);

  it("non-install command does not trigger OSV lookup", async () => {
    const result = await assessCommandLive("npm run build");
    expect(result.risk_level).toBe("none");
    expect(result.partial).toBeUndefined();
  }, LIVE_TIMEOUT);
});
