import { readFile } from "fs/promises";
import { readdir, stat } from "fs/promises";
import { basename, join } from "path";
import { parseManifest } from "./extractors/manifests.js";
import { queryOsv, getCvssScore, cvssToSeverity } from "./analyzers/package-vuln.js";
import type { ManifestPackage } from "./extractors/manifests.js";
import type { Finding } from "./types.js";

const MANIFEST_FILES = new Set([
  "package.json",
  "package-lock.json",
  "requirements.txt",
  "cargo.lock",
]);

const CONCURRENCY_LIMIT = 10;

export interface DepScanResult {
  file: string;
  packages_scanned: number;
  findings: Finding[];
  partial: boolean;
}

export interface DepScanSummary {
  files_scanned: number;
  total_packages: number;
  total_vulnerabilities: number;
  results: DepScanResult[];
}

/**
 * Scan a single manifest file for known vulnerabilities.
 */
export async function scanManifest(
  filePath: string,
  osvTimeout: number,
  allowlist: Set<string>,
): Promise<DepScanResult> {
  const content = await readFile(filePath, "utf-8");
  const packages = parseManifest(filePath, content);

  // Filter allowlisted and versionless packages
  const toCheck = packages.filter(pkg => {
    if (!pkg.version) return false;
    const key = `${pkg.name}@${pkg.version}`.toLowerCase();
    return !allowlist.has(key) && !allowlist.has(pkg.name.toLowerCase());
  });

  const findings: Finding[] = [];
  let partial = false;

  // Query OSV in batches with concurrency limit
  for (let i = 0; i < toCheck.length; i += CONCURRENCY_LIMIT) {
    const batch = toCheck.slice(i, i + CONCURRENCY_LIMIT);
    const results = await Promise.all(
      batch.map(async (pkg) => {
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
          source: { file: filePath, context: `${pkg.name}@${pkg.version}` },
        });
        continue;
      }

      if (vulns.length === 0) continue;

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
        source: { file: filePath, context: `${pkg.name}@${pkg.version}` },
      });
    }
  }

  return {
    file: filePath,
    packages_scanned: toCheck.length,
    findings,
    partial,
  };
}

/**
 * Scan a directory for manifest files and check all dependencies.
 */
export async function scanDependencies(
  dirPath: string,
  osvTimeout: number,
  allowlist: string[],
): Promise<DepScanSummary> {
  const allowSet = new Set(allowlist.map(s => s.toLowerCase()));
  const manifests = await findManifests(dirPath);

  const results: DepScanResult[] = [];
  for (const manifest of manifests) {
    const result = await scanManifest(manifest, osvTimeout, allowSet);
    results.push(result);
  }

  return {
    files_scanned: manifests.length,
    total_packages: results.reduce((s, r) => s + r.packages_scanned, 0),
    total_vulnerabilities: results.reduce((s, r) => s + r.findings.length, 0),
    results,
  };
}

async function findManifests(dirPath: string): Promise<string[]> {
  const found: string[] = [];
  await walkForManifests(dirPath, found);
  return found;
}

async function walkForManifests(currentDir: string, out: string[]): Promise<void> {
  let entries;
  try {
    entries = await readdir(currentDir, { withFileTypes: true });
  } catch {
    return;
  }

  // If package-lock.json exists, prefer it over package.json (more complete)
  let hasLockfile = false;

  for (const entry of entries) {
    const fullPath = join(currentDir, entry.name);

    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "dist") continue;
      await walkForManifests(fullPath, out);
      continue;
    }

    if (!entry.isFile()) continue;

    const lower = entry.name.toLowerCase();
    if (lower === "package-lock.json") {
      hasLockfile = true;
      out.push(fullPath);
    } else if (lower === "requirements.txt" || lower === "cargo.lock") {
      out.push(fullPath);
    }
  }

  // Only include package.json if no lock file present (lock file is more complete)
  if (!hasLockfile) {
    for (const entry of entries) {
      if (entry.isFile() && entry.name.toLowerCase() === "package.json") {
        out.push(join(currentDir, entry.name));
        break;
      }
    }
  }
}
