import type { PackageInfo } from "../analyzers/package-vuln.js";

export interface ManifestPackage extends PackageInfo {
  source: string; // e.g. "package.json", "requirements.txt"
}

/**
 * Parse package.json for direct dependencies with pinned versions.
 */
export function parsePackageJson(content: string, source = "package.json"): ManifestPackage[] {
  try {
    const pkg = JSON.parse(content);
    const deps: ManifestPackage[] = [];

    for (const depGroup of ["dependencies", "devDependencies"]) {
      const group = pkg[depGroup];
      if (!group || typeof group !== "object") continue;

      for (const [name, versionSpec] of Object.entries(group)) {
        if (typeof versionSpec !== "string") continue;
        // Extract exact or pinned version (strip ^, ~, >=, etc.)
        const version = extractSemver(versionSpec);
        if (version) {
          deps.push({ name, version, ecosystem: "npm", source });
        }
      }
    }

    return deps;
  } catch {
    return [];
  }
}

/**
 * Parse package-lock.json (v2/v3) for all resolved packages.
 */
export function parsePackageLockJson(content: string, source = "package-lock.json"): ManifestPackage[] {
  try {
    const lock = JSON.parse(content);
    const deps: ManifestPackage[] = [];

    // v2/v3 format: "packages" field
    if (lock.packages && typeof lock.packages === "object") {
      for (const [key, value] of Object.entries(lock.packages)) {
        const pkg = value as Record<string, unknown>;
        if (!key || key === "") continue; // Root package
        const name = key.replace(/^node_modules\//, "");
        const version = typeof pkg.version === "string" ? pkg.version : null;
        if (version) {
          deps.push({ name, version, ecosystem: "npm", source });
        }
      }
      return deps;
    }

    // v1 format: "dependencies" field (nested)
    if (lock.dependencies && typeof lock.dependencies === "object") {
      extractV1Dependencies(lock.dependencies, deps, source);
    }

    return deps;
  } catch {
    return [];
  }
}

function extractV1Dependencies(
  deps: Record<string, unknown>,
  out: ManifestPackage[],
  source: string,
): void {
  for (const [name, value] of Object.entries(deps)) {
    const pkg = value as Record<string, unknown>;
    const version = typeof pkg.version === "string" ? pkg.version : null;
    if (version) {
      out.push({ name, version, ecosystem: "npm", source });
    }
    // Recurse into nested dependencies
    if (pkg.dependencies && typeof pkg.dependencies === "object") {
      extractV1Dependencies(pkg.dependencies as Record<string, unknown>, out, source);
    }
  }
}

/**
 * Parse requirements.txt for Python packages with pinned versions.
 */
export function parseRequirementsTxt(content: string, source = "requirements.txt"): ManifestPackage[] {
  const deps: ManifestPackage[] = [];

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;

    // Match: package==version or package===version
    const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*={2,3}\s*([^\s;#]+)/);
    if (match) {
      deps.push({ name: match[1], version: match[2], ecosystem: "PyPI", source });
    }
  }

  return deps;
}

/**
 * Parse Cargo.lock for Rust crate versions.
 */
export function parseCargoLock(content: string, source = "Cargo.lock"): ManifestPackage[] {
  const deps: ManifestPackage[] = [];

  // Match [[package]] sections
  const packageRegex = /\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g;
  let match: RegExpExecArray | null;

  while ((match = packageRegex.exec(content)) !== null) {
    deps.push({ name: match[1], version: match[2], ecosystem: "crates.io", source });
  }

  return deps;
}

/**
 * Detect manifest type from filename and parse accordingly.
 */
export function parseManifest(filename: string, content: string): ManifestPackage[] {
  const base = filename.toLowerCase().replace(/\\/g, "/").split("/").pop() ?? "";

  if (base === "package-lock.json") return parsePackageLockJson(content, filename);
  if (base === "package.json") return parsePackageJson(content, filename);
  if (base === "requirements.txt") return parseRequirementsTxt(content, filename);
  if (base === "cargo.lock") return parseCargoLock(content, filename);

  return [];
}

/**
 * Extract a semver-like version from an npm version specifier.
 * Returns null for ranges that can't be pinpointed (e.g. "^1.x").
 */
function extractSemver(spec: string): string | null {
  // Strip leading ^, ~, =, v
  const cleaned = spec.replace(/^[\^~=v]+/, "").trim();
  // Match semver: 1.2.3 or 1.2.3-beta.1
  if (/^\d+\.\d+\.\d+/.test(cleaned)) {
    return cleaned;
  }
  return null;
}
