import { readFile } from "fs/promises";
import { readdir, stat } from "fs/promises";
import { basename, extname, join, relative } from "path";
import { parseCommand } from "./parser.js";
import { scoreRisk } from "./scorer.js";
import { extractShellCommands } from "./extractors/shell.js";
import { extractDockerfileCommands } from "./extractors/dockerfile.js";
import { extractCiCommands } from "./extractors/ci.js";
import type { ExtractedCommand } from "./extractors/shell.js";
import type { Analyzer, ActionPolicy, Finding, RiskAssessment, SourceLocation } from "./types.js";

export interface FileAnalysisResult {
  file: string;
  findings: Finding[];
  risk_level: RiskAssessment["risk_level"];
  commands_analyzed: number;
}

export interface DirectoryAnalysisResult {
  files_scanned: number;
  total_findings: number;
  results: FileAnalysisResult[];
}

type FileType = "shell" | "dockerfile" | "ci" | "unknown";

function detectFileType(filePath: string): FileType {
  const base = basename(filePath).toLowerCase();
  const ext = extname(filePath).toLowerCase();
  const normalized = filePath.replace(/\\/g, "/");

  if (base === "dockerfile" || base.startsWith("dockerfile.")) return "dockerfile";
  if (ext === ".sh" || ext === ".bash" || ext === ".zsh") return "shell";

  // GitHub Actions workflows
  if (normalized.includes(".github/workflows") && (ext === ".yml" || ext === ".yaml")) return "ci";
  // GitLab CI
  if (base === ".gitlab-ci.yml" || base === ".gitlab-ci.yaml") return "ci";

  return "unknown";
}

function extractCommands(content: string, fileType: FileType): ExtractedCommand[] {
  switch (fileType) {
    case "shell":
      return extractShellCommands(content);
    case "dockerfile":
      return extractDockerfileCommands(content);
    case "ci":
      return extractCiCommands(content);
    default:
      return [];
  }
}

/**
 * Analyze a single file for security risks.
 */
export async function analyzeFile(
  filePath: string,
  analyzers: Analyzer[],
  actionPolicy: ActionPolicy,
): Promise<FileAnalysisResult> {
  const content = await readFile(filePath, "utf-8");
  const fileType = detectFileType(filePath);

  if (fileType === "unknown") {
    return { file: filePath, findings: [], risk_level: "none", commands_analyzed: 0 };
  }

  const extracted = extractCommands(content, fileType);
  const allFindings: Finding[] = [];

  for (const { command, line } of extracted) {
    try {
      const parsed = parseCommand(command);
      if (parsed.length === 0) continue;

      const results = await Promise.all(
        analyzers.map(async (a) => {
          const result = await a.analyze(parsed, ".");
          for (const finding of result.findings) {
            finding.analyzer = a.name;
            finding.source = { file: filePath, line, context: command };
          }
          return result;
        })
      );

      const findings = results.flatMap(r => r.findings);
      allFindings.push(...findings);
    } catch {
      // Skip unparseable commands (e.g. complex shell constructs)
    }
  }

  const assessment = scoreRisk([{ findings: allFindings }], actionPolicy);

  return {
    file: filePath,
    findings: allFindings,
    risk_level: assessment.risk_level,
    commands_analyzed: extracted.length,
  };
}

const DEFAULT_PATTERNS = ["**/*.sh", "**/Dockerfile", "**/Dockerfile.*", "**/.github/workflows/*.yml", "**/.github/workflows/*.yaml", "**/.gitlab-ci.yml"];

/**
 * Recursively scan a directory for files matching patterns and analyze them.
 */
export async function analyzeDirectory(
  dirPath: string,
  analyzers: Analyzer[],
  actionPolicy: ActionPolicy,
  patterns?: string[],
): Promise<DirectoryAnalysisResult> {
  const effectivePatterns = patterns ?? DEFAULT_PATTERNS;
  const files = await collectFiles(dirPath, effectivePatterns);

  const results: FileAnalysisResult[] = [];
  for (const file of files) {
    const result = await analyzeFile(file, analyzers, actionPolicy);
    if (result.findings.length > 0 || result.commands_analyzed > 0) {
      results.push(result);
    }
  }

  return {
    files_scanned: files.length,
    total_findings: results.reduce((sum, r) => sum + r.findings.length, 0),
    results,
  };
}

/**
 * Collect files matching glob-like patterns via recursive directory walk.
 * Supports simple patterns: *.sh, Dockerfile, workflows/*.yml
 */
async function collectFiles(dirPath: string, patterns: string[]): Promise<string[]> {
  const matched: string[] = [];
  await walkDir(dirPath, dirPath, patterns, matched);
  return matched;
}

async function walkDir(rootDir: string, currentDir: string, patterns: string[], out: string[]): Promise<void> {
  let entries;
  try {
    entries = await readdir(currentDir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = join(currentDir, entry.name);

    // Skip common non-interesting directories
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "dist" || entry.name === "vendor") {
        continue;
      }
      await walkDir(rootDir, fullPath, patterns, out);
      continue;
    }

    if (!entry.isFile()) continue;

    const relPath = relative(rootDir, fullPath).replace(/\\/g, "/");
    if (matchesAnyPattern(relPath, entry.name, patterns)) {
      out.push(fullPath);
    }
  }
}

function matchesAnyPattern(relPath: string, fileName: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (matchPattern(relPath, fileName, pattern)) return true;
  }
  return false;
}

function matchPattern(relPath: string, fileName: string, pattern: string): boolean {
  // Normalize pattern separators
  const p = pattern.replace(/\\/g, "/");

  if (p.startsWith("**/")) {
    // Recursive glob: match against relative path
    const suffix = p.slice(3);
    if (suffix.includes("/")) {
      // e.g. **/.github/workflows/*.yml — match path ending
      return matchWildcard(relPath, suffix);
    }
    // e.g. **/*.sh — match filename
    return matchWildcard(fileName, suffix);
  }

  if (p.includes("/")) {
    return matchWildcard(relPath, p);
  }

  // Simple pattern: match filename
  return matchWildcard(fileName, p);
}

function matchWildcard(str: string, pattern: string): boolean {
  // Convert simple glob to regex: * → [^/]*, ** → .*, ? → .
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "⚑")
    .replace(/\*/g, "[^/]*")
    .replace(/⚑/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i").test(str);
}
