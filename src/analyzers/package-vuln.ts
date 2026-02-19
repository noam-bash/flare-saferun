import type { Analyzer, AnalyzerResult, Finding, ParsedCommand } from "../types.js";

interface OsvVulnerability {
  id: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
}

interface PackageInfo {
  name: string;
  version: string | null;
  ecosystem: string;
}

const ECOSYSTEM_MAP: Record<string, { verbs: string[]; ecosystem: string; parseArgs: (args: string[]) => PackageInfo[] }> = {
  npm: {
    verbs: ["npm"],
    ecosystem: "npm",
    parseArgs: (args) => {
      // npm install pkg@version or npm install pkg
      const installIdx = args.findIndex(a => a === "install" || a === "i" || a === "add");
      if (installIdx === -1) return [];
      return args.slice(installIdx + 1)
        .filter(a => !a.startsWith("-"))
        .map(a => {
          // Handle scoped packages: @scope/pkg@version
          const lastAt = a.lastIndexOf("@");
          if (lastAt > 0) {
            return { name: a.slice(0, lastAt), version: a.slice(lastAt + 1), ecosystem: "npm" };
          }
          return { name: a, version: null, ecosystem: "npm" };
        });
    },
  },
  pip: {
    verbs: ["pip", "pip3"],
    ecosystem: "PyPI",
    parseArgs: (args) => {
      const installIdx = args.findIndex(a => a === "install");
      if (installIdx === -1) return [];
      return args.slice(installIdx + 1)
        .filter(a => !a.startsWith("-"))
        .map(a => {
          // pip install pkg==version or pkg>=version
          const match = a.match(/^([^=<>!]+?)(?:==|>=|<=|~=|!=)(.+)$/);
          if (match) {
            return { name: match[1], version: match[2], ecosystem: "PyPI" };
          }
          return { name: a, version: null, ecosystem: "PyPI" };
        });
    },
  },
  cargo: {
    verbs: ["cargo"],
    ecosystem: "crates.io",
    parseArgs: (args) => {
      const addIdx = args.findIndex(a => a === "add" || a === "install");
      if (addIdx === -1) return [];
      return args.slice(addIdx + 1)
        .filter(a => !a.startsWith("-"))
        .map(a => {
          const atIdx = a.lastIndexOf("@");
          if (atIdx > 0) {
            return { name: a.slice(0, atIdx), version: a.slice(atIdx + 1), ecosystem: "crates.io" };
          }
          return { name: a, version: null, ecosystem: "crates.io" };
        });
    },
  },
};

// In-memory cache for OSV results, bounded to prevent memory leaks
const OSV_CACHE_MAX = 500;
const osvCache = new Map<string, OsvVulnerability[]>();

interface OsvResult {
  vulns: OsvVulnerability[];
  error?: string;
}

async function queryOsv(pkg: PackageInfo, timeout: number): Promise<OsvResult> {
  if (!pkg.version) return { vulns: [] }; // Can't query without a version

  const cacheKey = `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
  const cached = osvCache.get(cacheKey);
  if (cached) return { vulns: cached };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: { name: pkg.name, ecosystem: pkg.ecosystem },
        version: pkg.version,
      }),
      signal: controller.signal,
    });

    if (!response.ok) return { vulns: [], error: `OSV API returned HTTP ${response.status}` };

    const data = (await response.json()) as { vulns?: OsvVulnerability[] };
    const vulns = data.vulns ?? [];
    // Evict oldest entry if cache is full
    if (osvCache.size >= OSV_CACHE_MAX) {
      const oldest = osvCache.keys().next().value;
      if (oldest !== undefined) osvCache.delete(oldest);
    }
    osvCache.set(cacheKey, vulns);
    return { vulns };
  } catch (err) {
    const isTimeout = err instanceof DOMException && err.name === "AbortError";
    const reason = isTimeout ? "request timed out" : "network error";
    return { vulns: [], error: `OSV lookup failed: ${reason}` };
  } finally {
    clearTimeout(timer);
  }
}

function getCvssScore(vuln: OsvVulnerability): number | null {
  if (!vuln.severity) return null;
  const cvss = vuln.severity.find(s => s.type === "CVSS_V3" || s.type === "CVSS_V2");
  if (!cvss) return null;

  // Try numeric score first (e.g. "9.8")
  const numeric = parseFloat(cvss.score);
  if (!isNaN(numeric) && numeric >= 0 && numeric <= 10) return numeric;

  // OSV.dev often returns CVSS vector strings like "CVSS:3.1/AV:N/AC:L/..."
  // Approximate a base score from impact metrics
  if (cvss.score.startsWith("CVSS:")) {
    return approximateScoreFromVector(cvss.score);
  }

  return null;
}

/**
 * Approximate a CVSS v3 base score from the vector string.
 * This is a rough heuristic — not a full CVSS calculator — but good enough
 * to distinguish critical/high/medium/low for alerting purposes.
 */
function approximateScoreFromVector(vector: string): number {
  const metrics: Record<string, string> = {};
  for (const part of vector.split("/")) {
    const [key, val] = part.split(":");
    if (key && val) metrics[key] = val;
  }

  // Confidentiality, Integrity, Availability impact
  const impactValues: Record<string, number> = { N: 0, L: 1, H: 2 };
  const ci = impactValues[metrics["VC"] ?? metrics["C"] ?? "N"] ?? 0;
  const ii = impactValues[metrics["VI"] ?? metrics["I"] ?? "N"] ?? 0;
  const ai = impactValues[metrics["VA"] ?? metrics["A"] ?? "N"] ?? 0;
  const maxImpact = Math.max(ci, ii, ai);

  // Attack complexity and privileges required
  const acLow = (metrics["AC"] ?? "H") === "L";
  const prNone = (metrics["PR"] ?? "H") === "N";

  // Heuristic scoring based on impact + exploitability
  if (maxImpact === 0) return 0;
  let score = maxImpact === 2 ? 7.0 : 4.0; // High impact base 7, Low impact base 4
  if (acLow) score += 1.0;
  if (prNone) score += 1.0;
  // Scope changed adds severity
  if (metrics["S"] === "C") score += 0.5;

  return Math.min(score, 10);
}

function cvssToSeverity(score: number | null): Finding["severity"] {
  if (score === null) return "medium"; // Unknown CVSS, assume medium
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

export function createPackageVulnAnalyzer(osvTimeout = 1500): Analyzer {
  return {
    name: "package-vuln",

    async analyze(parsed: ParsedCommand[]): Promise<AnalyzerResult> {
      const findings: Finding[] = [];
      const packages: PackageInfo[] = [];
      let partial = false;

      // Extract packages from all command segments
      for (const cmd of parsed) {
        for (const [, config] of Object.entries(ECOSYSTEM_MAP)) {
          if (config.verbs.includes(cmd.verb)) {
            packages.push(...config.parseArgs(cmd.args));
          }
        }

        // Handle: sudo npm install, sudo pip install
        if (cmd.verb === "sudo" && cmd.args.length > 0) {
          const innerVerb = cmd.args[0];
          for (const [, config] of Object.entries(ECOSYSTEM_MAP)) {
            if (config.verbs.includes(innerVerb)) {
              packages.push(...config.parseArgs(cmd.args.slice(1)));
            }
          }
        }
      }

      if (packages.length === 0) return { findings };

      // Query OSV.dev for each package in parallel
      const results = await Promise.all(
        packages.map(async (pkg) => {
          const result = await queryOsv(pkg, osvTimeout);
          return { pkg, ...result };
        })
      );

      for (const { pkg, vulns, error } of results) {
        if (error) {
          partial = true;
          findings.push({
            category: "package-vulnerability",
            severity: "medium",
            description: `\`${pkg.name}@${pkg.version}\` — ${error}; vulnerability status unknown`,
          });
          continue;
        }

        if (vulns.length === 0) continue;

        // Find highest CVSS score
        let highestScore: number | null = null;
        const cveIds: string[] = [];

        for (const vuln of vulns) {
          const score = getCvssScore(vuln);
          if (score !== null && (highestScore === null || score > highestScore)) {
            highestScore = score;
          }
          if (vuln.id.startsWith("CVE-") || vuln.id.startsWith("GHSA-")) {
            cveIds.push(vuln.id);
          }
        }

        const severity = cvssToSeverity(highestScore);
        const scoreText = highestScore !== null ? ` (CVSS ${highestScore.toFixed(1)})` : "";
        const cveText = cveIds.length > 0
          ? ` including ${cveIds.slice(0, 3).join(", ")}${cveIds.length > 3 ? ` and ${cveIds.length - 3} more` : ""}`
          : "";

        findings.push({
          category: "package-vulnerability",
          severity,
          description: `\`${pkg.name}@${pkg.version}\` has ${vulns.length} known vulnerabilit${vulns.length === 1 ? "y" : "ies"}${cveText}${scoreText}`,
        });
      }

      return { findings, partial };
    },
  };
}

export const packageVulnAnalyzer = createPackageVulnAnalyzer();
