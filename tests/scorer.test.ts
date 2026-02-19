import { describe, it, expect } from "vitest";
import { scoreRisk } from "../src/scorer.js";
import type { AnalyzerResult, ActionPolicy } from "../src/types.js";

describe("scoreRisk", () => {
  it("returns none for empty findings", () => {
    const result = scoreRisk([{ findings: [] }]);
    expect(result.risk_level).toBe("none");
    expect(result.details).toHaveLength(0);
  });

  it("returns the highest individual severity", () => {
    const result = scoreRisk([
      {
        findings: [
          { category: "destructive", severity: "high", description: "rm -rf" },
          { category: "permissions", severity: "low", description: "sudo" },
        ],
      },
    ]);
    expect(result.risk_level).toBe("high");
  });

  it("amplifies 2+ high findings to critical", () => {
    const result = scoreRisk([
      {
        findings: [
          { category: "destructive", severity: "high", description: "issue 1" },
          { category: "network", severity: "high", description: "issue 2" },
        ],
      },
    ]);
    expect(result.risk_level).toBe("critical");
  });

  it("amplifies 3+ medium findings to high", () => {
    const result = scoreRisk([
      {
        findings: [
          { category: "a", severity: "medium", description: "issue 1" },
          { category: "b", severity: "medium", description: "issue 2" },
          { category: "c", severity: "medium", description: "issue 3" },
        ],
      },
    ]);
    expect(result.risk_level).toBe("high");
  });

  it("amplifies dangerous category combos", () => {
    const result = scoreRisk([
      {
        findings: [
          { category: "permissions", severity: "high", description: "sudo" },
          { category: "network", severity: "medium", description: "curl" },
        ],
      },
    ]);
    expect(result.risk_level).toBe("critical");
  });

  it("includes all findings in details", () => {
    const results: AnalyzerResult[] = [
      { findings: [{ category: "a", severity: "low", description: "one" }] },
      { findings: [{ category: "b", severity: "medium", description: "two" }] },
    ];
    const assessment = scoreRisk(results);
    expect(assessment.details).toHaveLength(2);
  });

  it("generates a summary with the risk level", () => {
    const result = scoreRisk([
      {
        findings: [
          { category: "destructive", severity: "critical", description: "rm -rf /" },
        ],
      },
    ]);
    expect(result.summary).toContain("Critical risk");
  });

  it("generates a recommendation", () => {
    const result = scoreRisk([
      {
        findings: [
          { category: "destructive", severity: "critical", description: "rm -rf /" },
        ],
      },
    ]);
    expect(result.recommendation.length).toBeGreaterThan(0);
  });
});

describe("scoreRisk action field", () => {
  it("returns action 'run' for none risk level", () => {
    const result = scoreRisk([{ findings: [] }]);
    expect(result.action).toBe("run");
  });

  it("returns action 'warn' for medium risk level", () => {
    const result = scoreRisk([
      {
        findings: [
          { category: "network", severity: "medium", description: "HTTP" },
        ],
      },
    ]);
    expect(result.action).toBe("warn");
  });

  it("returns action 'ask' for high risk level", () => {
    const result = scoreRisk([
      {
        findings: [
          { category: "network", severity: "high", description: "netcat" },
        ],
      },
    ]);
    expect(result.action).toBe("ask");
  });

  it("returns action 'ask' for critical risk level", () => {
    const result = scoreRisk([
      {
        findings: [
          { category: "destructive", severity: "critical", description: "rm -rf /" },
        ],
      },
    ]);
    expect(result.action).toBe("ask");
  });

  it("respects custom action policy", () => {
    const customPolicy: ActionPolicy = {
      none: "run",
      low: "run",
      medium: "run",
      high: "warn",
      critical: "ask",
    };
    const result = scoreRisk(
      [{ findings: [{ category: "network", severity: "medium", description: "HTTP" }] }],
      customPolicy,
    );
    expect(result.action).toBe("run");
  });

  it("respects custom policy for high level", () => {
    const customPolicy: ActionPolicy = {
      none: "run",
      low: "run",
      medium: "run",
      high: "warn",
      critical: "ask",
    };
    const result = scoreRisk(
      [{ findings: [{ category: "network", severity: "high", description: "netcat" }] }],
      customPolicy,
    );
    expect(result.action).toBe("warn");
  });
});
