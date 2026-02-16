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

// In-memory cache for OSV results
const osvCache = new Map<string, OsvVulnerability[]>();

async function queryOsv(pkg: PackageInfo, timeout: number): Promise<OsvVulnerability[]> {
  if (!pkg.version) return []; // Can't query without a version

  const cacheKey = `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
  const cached = osvCache.get(cacheKey);
  if (cached) return cached;

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

    if (!response.ok) return [];

    const data = (await response.json()) as { vulns?: OsvVulnerability[] };
    const vulns = data.vulns ?? [];
    osvCache.set(cacheKey, vulns);
    return vulns;
  } catch {
    return []; // Timeout or network error — degrade gracefully
  } finally {
    clearTimeout(timer);
  }
}

function getCvssScore(vuln: OsvVulnerability): number | null {
  if (!vuln.severity) return null;
  const cvss = vuln.severity.find(s => s.type === "CVSS_V3" || s.type === "CVSS_V2");
  if (!cvss) return null;
  const score = parseFloat(cvss.score);
  return isNaN(score) ? null : score;
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
          const vulns = await queryOsv(pkg, osvTimeout);
          return { pkg, vulns };
        })
      );

      for (const { pkg, vulns } of results) {
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

      return { findings };
    },
  };
}

export const packageVulnAnalyzer = createPackageVulnAnalyzer();
