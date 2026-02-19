import type { ActionPolicy, AnalyzerResult, Finding, RiskAssessment, RiskLevel } from "./types.js";

const SEVERITY_ORDER: RiskLevel[] = ["none", "low", "medium", "high", "critical"];

const DEFAULT_ACTION_POLICY: ActionPolicy = {
  none: "run",
  low: "run",
  medium: "warn",
  high: "ask",
  critical: "ask",
};

function severityIndex(level: RiskLevel): number {
  return SEVERITY_ORDER.indexOf(level);
}

/**
 * Aggregate findings from all analyzers into a single RiskAssessment.
 */
export function scoreRisk(results: AnalyzerResult[], actionPolicy: ActionPolicy = DEFAULT_ACTION_POLICY): RiskAssessment {
  const allFindings = results.flatMap(r => r.findings);
  const partial = results.some(r => r.partial);

  if (allFindings.length === 0) {
    return {
      risk_level: "none",
      action: actionPolicy.none,
      summary: "No security concerns detected.",
      details: [],
      recommendation: "Command appears safe to execute.",
      ...(partial && { partial }),
    };
  }

  const riskLevel = determineRiskLevel(allFindings);
  const summary = generateSummary(allFindings, riskLevel);
  const recommendation = generateRecommendation(allFindings, riskLevel);

  return {
    risk_level: riskLevel,
    action: actionPolicy[riskLevel],
    summary,
    details: allFindings.map(f => ({
      category: f.category,
      severity: f.severity,
      description: f.description,
    })),
    recommendation,
    ...(partial && { partial }),
  };
}

function determineRiskLevel(findings: Finding[]): RiskLevel {
  // Find highest individual severity
  let maxLevel: RiskLevel = "none";
  for (const f of findings) {
    if (severityIndex(f.severity) > severityIndex(maxLevel)) {
      maxLevel = f.severity;
    }
  }

  // Apply amplification rules
  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;

  if (criticalCount >= 1) return "critical";

  if (highCount >= 2) return "critical";

  if (highCount >= 1 && mediumCount >= 1) {
    const categories = new Set(findings.map(f => f.category));
    const dangerousCombos = [
      ["permissions", "network"],
      ["permissions", "sensitive-path"],
      ["network", "sensitive-path"],
    ];
    for (const [a, b] of dangerousCombos) {
      if (categories.has(a) && categories.has(b)) return "critical";
    }
  }

  if (mediumCount >= 3) return "high";

  return maxLevel;
}

function generateSummary(findings: Finding[], level: RiskLevel): string {
  // Sort by severity descending, take top 3
  const sorted = [...findings].sort(
    (a, b) => severityIndex(b.severity) - severityIndex(a.severity)
  );
  const top = sorted.slice(0, 3);

  const levelLabel: Record<RiskLevel, string> = {
    none: "No issues",
    low: "Low risk",
    medium: "Medium risk",
    high: "High risk",
    critical: "Critical risk",
  };

  const prefix = `**${levelLabel[level]}**`;

  if (top.length === 1) {
    return `${prefix}: ${top[0].description}`;
  }

  const bullets = top.map(f => `- ${f.description}`).join("\n");
  return `${prefix} — ${findings.length} issue${findings.length > 1 ? "s" : ""} found:\n${bullets}`;
}

function generateRecommendation(findings: Finding[], level: RiskLevel): string {
  const categories = new Set(findings.map(f => f.category));

  if (level === "critical") {
    if (categories.has("destructive")) {
      return "This command performs irreversible destructive operations. Verify the targets carefully before proceeding.";
    }
    if (categories.has("network") && categories.has("sensitive-path")) {
      return "This command may exfiltrate sensitive data over the network. Do not proceed unless you trust the destination.";
    }
    if (categories.has("package-vulnerability")) {
      const vulnFinding = findings.find(f => f.category === "package-vulnerability");
      return `Consider upgrading to a patched version. ${vulnFinding?.description ?? ""}`;
    }
    return "This command has critical security concerns. Review carefully before proceeding.";
  }

  if (level === "high") {
    if (categories.has("package-vulnerability")) {
      return "Consider using a newer version of the package with known vulnerabilities patched.";
    }
    if (categories.has("permissions")) {
      return "Verify that the permission changes are intentional and the target paths are correct.";
    }
    if (categories.has("network")) {
      return "Verify the network destination is trusted before sending data.";
    }
    return "Review the flagged issues before proceeding.";
  }

  if (level === "medium") {
    return "Minor concerns detected. Review the details and proceed if expected.";
  }

  return "Low-risk issues noted for awareness. Generally safe to proceed.";
}
